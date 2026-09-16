rule TTP_XOR_QUAD_CurrentVersionRun_d3e4 {
  strings:
    $key_d3e4 = { 80 8b [2] a4 85 [2] 8f a9 [2] a1 8b [2] b5 90 [2] ba 8a [2] a4 97 [2] a6 96 [2] bd 90 [2] a1 97 [2] bd b8 }

  condition:
    any of them
}