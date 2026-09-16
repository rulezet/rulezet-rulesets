rule TTP_XOR_QUAD_CurrentVersionRun_d3c7 {
  strings:
    $key_d3c7 = { 80 a8 [2] a4 a6 [2] 8f 8a [2] a1 a8 [2] b5 b3 [2] ba a9 [2] a4 b4 [2] a6 b5 [2] bd b3 [2] a1 b4 [2] bd 9b }

  condition:
    any of them
}