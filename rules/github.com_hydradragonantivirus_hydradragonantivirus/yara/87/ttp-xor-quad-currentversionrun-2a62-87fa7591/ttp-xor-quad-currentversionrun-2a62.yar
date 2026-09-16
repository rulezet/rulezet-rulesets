rule TTP_XOR_QUAD_CurrentVersionRun_2a62 {
  strings:
    $key_2a62 = { 79 0d [2] 5d 03 [2] 76 2f [2] 58 0d [2] 4c 16 [2] 43 0c [2] 5d 11 [2] 5f 10 [2] 44 16 [2] 58 11 [2] 44 3e }

  condition:
    any of them
}