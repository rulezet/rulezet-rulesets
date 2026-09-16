rule TTP_XOR_QUAD_CurrentVersionRun_2a66 {
  strings:
    $key_2a66 = { 79 09 [2] 5d 07 [2] 76 2b [2] 58 09 [2] 4c 12 [2] 43 08 [2] 5d 15 [2] 5f 14 [2] 44 12 [2] 58 15 [2] 44 3a }

  condition:
    any of them
}