rule TTP_XOR_QUAD_CurrentVersionRun_1f66 {
  strings:
    $key_1f66 = { 4c 09 [2] 68 07 [2] 43 2b [2] 6d 09 [2] 79 12 [2] 76 08 [2] 68 15 [2] 6a 14 [2] 71 12 [2] 6d 15 [2] 71 3a }

  condition:
    any of them
}