rule TTP_XOR_QUAD_CurrentVersionRun_0ac6 {
  strings:
    $key_0ac6 = { 59 a9 [2] 7d a7 [2] 56 8b [2] 78 a9 [2] 6c b2 [2] 63 a8 [2] 7d b5 [2] 7f b4 [2] 64 b2 [2] 78 b5 [2] 64 9a }

  condition:
    any of them
}