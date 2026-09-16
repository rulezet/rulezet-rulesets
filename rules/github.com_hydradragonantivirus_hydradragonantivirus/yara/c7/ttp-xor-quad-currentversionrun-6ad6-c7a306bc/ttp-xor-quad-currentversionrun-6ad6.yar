rule TTP_XOR_QUAD_CurrentVersionRun_6ad6 {
  strings:
    $key_6ad6 = { 39 b9 [2] 1d b7 [2] 36 9b [2] 18 b9 [2] 0c a2 [2] 03 b8 [2] 1d a5 [2] 1f a4 [2] 04 a2 [2] 18 a5 [2] 04 8a }

  condition:
    any of them
}