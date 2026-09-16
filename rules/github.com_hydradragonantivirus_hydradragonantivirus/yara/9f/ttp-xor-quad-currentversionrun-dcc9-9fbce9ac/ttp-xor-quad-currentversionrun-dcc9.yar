rule TTP_XOR_QUAD_CurrentVersionRun_dcc9 {
  strings:
    $key_dcc9 = { 8f a6 [2] ab a8 [2] 80 84 [2] ae a6 [2] ba bd [2] b5 a7 [2] ab ba [2] a9 bb [2] b2 bd [2] ae ba [2] b2 95 }

  condition:
    any of them
}