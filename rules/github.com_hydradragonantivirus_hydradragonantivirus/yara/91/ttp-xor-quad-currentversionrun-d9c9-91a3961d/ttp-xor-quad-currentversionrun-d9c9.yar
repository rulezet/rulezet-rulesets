rule TTP_XOR_QUAD_CurrentVersionRun_d9c9 {
  strings:
    $key_d9c9 = { 8a a6 [2] ae a8 [2] 85 84 [2] ab a6 [2] bf bd [2] b0 a7 [2] ae ba [2] ac bb [2] b7 bd [2] ab ba [2] b7 95 }

  condition:
    any of them
}