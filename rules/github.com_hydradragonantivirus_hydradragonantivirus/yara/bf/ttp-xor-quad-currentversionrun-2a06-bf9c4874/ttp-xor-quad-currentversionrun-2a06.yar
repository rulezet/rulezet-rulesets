rule TTP_XOR_QUAD_CurrentVersionRun_2a06 {
  strings:
    $key_2a06 = { 79 69 [2] 5d 67 [2] 76 4b [2] 58 69 [2] 4c 72 [2] 43 68 [2] 5d 75 [2] 5f 74 [2] 44 72 [2] 58 75 [2] 44 5a }

  condition:
    any of them
}