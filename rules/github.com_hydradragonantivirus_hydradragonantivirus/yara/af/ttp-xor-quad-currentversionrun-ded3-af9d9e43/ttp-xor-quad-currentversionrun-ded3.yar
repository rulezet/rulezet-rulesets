rule TTP_XOR_QUAD_CurrentVersionRun_ded3 {
  strings:
    $key_ded3 = { 8d bc [2] a9 b2 [2] 82 9e [2] ac bc [2] b8 a7 [2] b7 bd [2] a9 a0 [2] ab a1 [2] b0 a7 [2] ac a0 [2] b0 8f }

  condition:
    any of them
}