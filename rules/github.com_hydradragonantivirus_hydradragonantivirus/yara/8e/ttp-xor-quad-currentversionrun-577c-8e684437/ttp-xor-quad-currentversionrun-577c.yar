rule TTP_XOR_QUAD_CurrentVersionRun_577c {
  strings:
    $key_577c = { 04 13 [2] 20 1d [2] 0b 31 [2] 25 13 [2] 31 08 [2] 3e 12 [2] 20 0f [2] 22 0e [2] 39 08 [2] 25 0f [2] 39 20 }

  condition:
    any of them
}