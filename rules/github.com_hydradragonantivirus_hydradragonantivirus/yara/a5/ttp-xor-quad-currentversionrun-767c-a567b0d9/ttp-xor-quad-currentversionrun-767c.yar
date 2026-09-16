rule TTP_XOR_QUAD_CurrentVersionRun_767c {
  strings:
    $key_767c = { 25 13 [2] 01 1d [2] 2a 31 [2] 04 13 [2] 10 08 [2] 1f 12 [2] 01 0f [2] 03 0e [2] 18 08 [2] 04 0f [2] 18 20 }

  condition:
    any of them
}