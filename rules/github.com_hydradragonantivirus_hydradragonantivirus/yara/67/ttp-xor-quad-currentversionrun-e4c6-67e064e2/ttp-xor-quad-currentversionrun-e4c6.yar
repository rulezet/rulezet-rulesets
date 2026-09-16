rule TTP_XOR_QUAD_CurrentVersionRun_e4c6 {
  strings:
    $key_e4c6 = { b7 a9 [2] 93 a7 [2] b8 8b [2] 96 a9 [2] 82 b2 [2] 8d a8 [2] 93 b5 [2] 91 b4 [2] 8a b2 [2] 96 b5 [2] 8a 9a }

  condition:
    any of them
}