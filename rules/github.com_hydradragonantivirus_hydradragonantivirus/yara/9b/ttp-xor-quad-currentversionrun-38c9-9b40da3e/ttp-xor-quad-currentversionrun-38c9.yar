rule TTP_XOR_QUAD_CurrentVersionRun_38c9 {
  strings:
    $key_38c9 = { 6b a6 [2] 4f a8 [2] 64 84 [2] 4a a6 [2] 5e bd [2] 51 a7 [2] 4f ba [2] 4d bb [2] 56 bd [2] 4a ba [2] 56 95 }

  condition:
    any of them
}