rule TTP_XOR_QUAD_CurrentVersionRun_2a47 {
  strings:
    $key_2a47 = { 79 28 [2] 5d 26 [2] 76 0a [2] 58 28 [2] 4c 33 [2] 43 29 [2] 5d 34 [2] 5f 35 [2] 44 33 [2] 58 34 [2] 44 1b }

  condition:
    any of them
}