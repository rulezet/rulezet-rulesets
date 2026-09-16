rule TTP_XOR_QUAD_CurrentVersionRun_ecca {
  strings:
    $key_ecca = { bf a5 [2] 9b ab [2] b0 87 [2] 9e a5 [2] 8a be [2] 85 a4 [2] 9b b9 [2] 99 b8 [2] 82 be [2] 9e b9 [2] 82 96 }

  condition:
    any of them
}