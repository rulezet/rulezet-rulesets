rule TTP_XOR_QUAD_CurrentVersionRun_d2d3 {
  strings:
    $key_d2d3 = { 81 bc [2] a5 b2 [2] 8e 9e [2] a0 bc [2] b4 a7 [2] bb bd [2] a5 a0 [2] a7 a1 [2] bc a7 [2] a0 a0 [2] bc 8f }

  condition:
    any of them
}