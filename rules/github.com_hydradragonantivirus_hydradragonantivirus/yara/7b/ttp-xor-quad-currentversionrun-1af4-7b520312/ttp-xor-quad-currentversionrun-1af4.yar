rule TTP_XOR_QUAD_CurrentVersionRun_1af4 {
  strings:
    $key_1af4 = { 49 9b [2] 6d 95 [2] 46 b9 [2] 68 9b [2] 7c 80 [2] 73 9a [2] 6d 87 [2] 6f 86 [2] 74 80 [2] 68 87 [2] 74 a8 }

  condition:
    any of them
}