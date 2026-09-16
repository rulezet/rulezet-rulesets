rule TTP_XOR_QUAD_CurrentVersionRun_ecc9 {
  strings:
    $key_ecc9 = { bf a6 [2] 9b a8 [2] b0 84 [2] 9e a6 [2] 8a bd [2] 85 a7 [2] 9b ba [2] 99 bb [2] 82 bd [2] 9e ba [2] 82 95 }

  condition:
    any of them
}