rule TTP_XOR_QUAD_CurrentVersionRun_06d7 {
  strings:
    $key_06d7 = { 55 b8 [2] 71 b6 [2] 5a 9a [2] 74 b8 [2] 60 a3 [2] 6f b9 [2] 71 a4 [2] 73 a5 [2] 68 a3 [2] 74 a4 [2] 68 8b }

  condition:
    any of them
}