rule TTP_XOR_QUAD_CurrentVersionRun_1f25 {
  strings:
    $key_1f25 = { 4c 4a [2] 68 44 [2] 43 68 [2] 6d 4a [2] 79 51 [2] 76 4b [2] 68 56 [2] 6a 57 [2] 71 51 [2] 6d 56 [2] 71 79 }

  condition:
    any of them
}