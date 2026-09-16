rule TTP_XOR_QUAD_CurrentVersionRun_627c {
  strings:
    $key_627c = { 31 13 [2] 15 1d [2] 3e 31 [2] 10 13 [2] 04 08 [2] 0b 12 [2] 15 0f [2] 17 0e [2] 0c 08 [2] 10 0f [2] 0c 20 }

  condition:
    any of them
}