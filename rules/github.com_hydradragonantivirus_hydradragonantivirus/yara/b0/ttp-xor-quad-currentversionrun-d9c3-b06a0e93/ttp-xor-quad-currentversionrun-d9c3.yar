rule TTP_XOR_QUAD_CurrentVersionRun_d9c3 {
  strings:
    $key_d9c3 = { 8a ac [2] ae a2 [2] 85 8e [2] ab ac [2] bf b7 [2] b0 ad [2] ae b0 [2] ac b1 [2] b7 b7 [2] ab b0 [2] b7 9f }

  condition:
    any of them
}