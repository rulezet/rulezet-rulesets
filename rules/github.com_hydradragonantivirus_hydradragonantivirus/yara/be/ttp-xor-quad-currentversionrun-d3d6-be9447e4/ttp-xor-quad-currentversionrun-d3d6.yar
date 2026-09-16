rule TTP_XOR_QUAD_CurrentVersionRun_d3d6 {
  strings:
    $key_d3d6 = { 80 b9 [2] a4 b7 [2] 8f 9b [2] a1 b9 [2] b5 a2 [2] ba b8 [2] a4 a5 [2] a6 a4 [2] bd a2 [2] a1 a5 [2] bd 8a }

  condition:
    any of them
}