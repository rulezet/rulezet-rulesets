rule TTP_XOR_QUAD_CurrentVersionRun_19c9 {
  strings:
    $key_19c9 = { 4a a6 [2] 6e a8 [2] 45 84 [2] 6b a6 [2] 7f bd [2] 70 a7 [2] 6e ba [2] 6c bb [2] 77 bd [2] 6b ba [2] 77 95 }

  condition:
    any of them
}