rule TTP_XOR_QUAD_CurrentVersionRun_1ff4 {
  strings:
    $key_1ff4 = { 4c 9b [2] 68 95 [2] 43 b9 [2] 6d 9b [2] 79 80 [2] 76 9a [2] 68 87 [2] 6a 86 [2] 71 80 [2] 6d 87 [2] 71 a8 }

  condition:
    any of them
}