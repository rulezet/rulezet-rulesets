rule TTP_XOR_QUAD_CurrentVersionRun_6ac6 {
  strings:
    $key_6ac6 = { 39 a9 [2] 1d a7 [2] 36 8b [2] 18 a9 [2] 0c b2 [2] 03 a8 [2] 1d b5 [2] 1f b4 [2] 04 b2 [2] 18 b5 [2] 04 9a }

  condition:
    any of them
}