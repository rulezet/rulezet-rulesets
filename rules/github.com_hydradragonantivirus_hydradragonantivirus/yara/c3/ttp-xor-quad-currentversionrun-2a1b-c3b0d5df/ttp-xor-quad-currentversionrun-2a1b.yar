rule TTP_XOR_QUAD_CurrentVersionRun_2a1b {
  strings:
    $key_2a1b = { 79 74 [2] 5d 7a [2] 76 56 [2] 58 74 [2] 4c 6f [2] 43 75 [2] 5d 68 [2] 5f 69 [2] 44 6f [2] 58 68 [2] 44 47 }

  condition:
    any of them
}