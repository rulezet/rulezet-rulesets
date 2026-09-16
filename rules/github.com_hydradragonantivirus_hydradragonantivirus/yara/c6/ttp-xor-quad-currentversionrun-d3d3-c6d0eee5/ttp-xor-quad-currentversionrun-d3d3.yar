rule TTP_XOR_QUAD_CurrentVersionRun_d3d3 {
  strings:
    $key_d3d3 = { 80 bc [2] a4 b2 [2] 8f 9e [2] a1 bc [2] b5 a7 [2] ba bd [2] a4 a0 [2] a6 a1 [2] bd a7 [2] a1 a0 [2] bd 8f }

  condition:
    any of them
}