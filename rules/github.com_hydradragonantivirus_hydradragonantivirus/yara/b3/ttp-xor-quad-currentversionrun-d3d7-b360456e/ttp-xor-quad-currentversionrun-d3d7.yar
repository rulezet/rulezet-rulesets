rule TTP_XOR_QUAD_CurrentVersionRun_d3d7 {
  strings:
    $key_d3d7 = { 80 b8 [2] a4 b6 [2] 8f 9a [2] a1 b8 [2] b5 a3 [2] ba b9 [2] a4 a4 [2] a6 a5 [2] bd a3 [2] a1 a4 [2] bd 8b }

  condition:
    any of them
}