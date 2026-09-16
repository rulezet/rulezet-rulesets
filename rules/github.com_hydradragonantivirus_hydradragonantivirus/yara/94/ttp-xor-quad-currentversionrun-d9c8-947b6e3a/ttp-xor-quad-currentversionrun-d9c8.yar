rule TTP_XOR_QUAD_CurrentVersionRun_d9c8 {
  strings:
    $key_d9c8 = { 8a a7 [2] ae a9 [2] 85 85 [2] ab a7 [2] bf bc [2] b0 a6 [2] ae bb [2] ac ba [2] b7 bc [2] ab bb [2] b7 94 }

  condition:
    any of them
}