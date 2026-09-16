rule TTP_XOR_QUAD_CurrentVersionRun_e7c6 {
  strings:
    $key_e7c6 = { b4 a9 [2] 90 a7 [2] bb 8b [2] 95 a9 [2] 81 b2 [2] 8e a8 [2] 90 b5 [2] 92 b4 [2] 89 b2 [2] 95 b5 [2] 89 9a }

  condition:
    any of them
}