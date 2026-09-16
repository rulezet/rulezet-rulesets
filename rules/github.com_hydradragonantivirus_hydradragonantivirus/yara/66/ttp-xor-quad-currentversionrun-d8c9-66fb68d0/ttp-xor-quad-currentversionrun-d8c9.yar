rule TTP_XOR_QUAD_CurrentVersionRun_d8c9 {
  strings:
    $key_d8c9 = { 8b a6 [2] af a8 [2] 84 84 [2] aa a6 [2] be bd [2] b1 a7 [2] af ba [2] ad bb [2] b6 bd [2] aa ba [2] b6 95 }

  condition:
    any of them
}