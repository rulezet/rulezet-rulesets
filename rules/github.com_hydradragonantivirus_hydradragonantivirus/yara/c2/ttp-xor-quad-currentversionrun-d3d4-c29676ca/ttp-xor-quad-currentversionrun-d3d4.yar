rule TTP_XOR_QUAD_CurrentVersionRun_d3d4 {
  strings:
    $key_d3d4 = { 80 bb [2] a4 b5 [2] 8f 99 [2] a1 bb [2] b5 a0 [2] ba ba [2] a4 a7 [2] a6 a6 [2] bd a0 [2] a1 a7 [2] bd 88 }

  condition:
    any of them
}