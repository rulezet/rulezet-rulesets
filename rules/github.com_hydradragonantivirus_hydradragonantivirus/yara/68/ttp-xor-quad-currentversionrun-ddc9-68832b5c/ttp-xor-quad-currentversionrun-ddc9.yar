rule TTP_XOR_QUAD_CurrentVersionRun_ddc9 {
  strings:
    $key_ddc9 = { 8e a6 [2] aa a8 [2] 81 84 [2] af a6 [2] bb bd [2] b4 a7 [2] aa ba [2] a8 bb [2] b3 bd [2] af ba [2] b3 95 }

  condition:
    any of them
}