rule TTP_XOR_QUAD_CurrentVersionRun_d3f5 {
  strings:
    $key_d3f5 = { 80 9a [2] a4 94 [2] 8f b8 [2] a1 9a [2] b5 81 [2] ba 9b [2] a4 86 [2] a6 87 [2] bd 81 [2] a1 86 [2] bd a9 }

  condition:
    any of them
}