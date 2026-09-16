rule TTP_XOR_QUAD_CurrentVersionRun_d9d5 {
  strings:
    $key_d9d5 = { 8a ba [2] ae b4 [2] 85 98 [2] ab ba [2] bf a1 [2] b0 bb [2] ae a6 [2] ac a7 [2] b7 a1 [2] ab a6 [2] b7 89 }

  condition:
    any of them
}