rule TTP_XOR_QUAD_CurrentVersionRun_d3c9 {
  strings:
    $key_d3c9 = { 80 a6 [2] a4 a8 [2] 8f 84 [2] a1 a6 [2] b5 bd [2] ba a7 [2] a4 ba [2] a6 bb [2] bd bd [2] a1 ba [2] bd 95 }

  condition:
    any of them
}