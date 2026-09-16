rule TTP_XOR_QUAD_CurrentVersionRun_d9d3 {
  strings:
    $key_d9d3 = { 8a bc [2] ae b2 [2] 85 9e [2] ab bc [2] bf a7 [2] b0 bd [2] ae a0 [2] ac a1 [2] b7 a7 [2] ab a0 [2] b7 8f }

  condition:
    any of them
}