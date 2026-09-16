rule TTP_XOR_QUAD_CurrentVersionRun_7ad6 {
  strings:
    $key_7ad6 = { 29 b9 [2] 0d b7 [2] 26 9b [2] 08 b9 [2] 1c a2 [2] 13 b8 [2] 0d a5 [2] 0f a4 [2] 14 a2 [2] 08 a5 [2] 14 8a }

  condition:
    any of them
}