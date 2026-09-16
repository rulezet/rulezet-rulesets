rule TTP_XOR_QUAD_CurrentVersionRun_d3c8 {
  strings:
    $key_d3c8 = { 80 a7 [2] a4 a9 [2] 8f 85 [2] a1 a7 [2] b5 bc [2] ba a6 [2] a4 bb [2] a6 ba [2] bd bc [2] a1 bb [2] bd 94 }

  condition:
    any of them
}