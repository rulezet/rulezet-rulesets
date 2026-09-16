rule TTP_XOR_QUAD_CurrentVersionRun_1ac7 {
  strings:
    $key_1ac7 = { 49 a8 [2] 6d a6 [2] 46 8a [2] 68 a8 [2] 7c b3 [2] 73 a9 [2] 6d b4 [2] 6f b5 [2] 74 b3 [2] 68 b4 [2] 74 9b }

  condition:
    any of them
}