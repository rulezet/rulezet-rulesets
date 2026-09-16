rule TTP_XOR_QUAD_CurrentVersionRun_d3fd {
  strings:
    $key_d3fd = { 80 92 [2] a4 9c [2] 8f b0 [2] a1 92 [2] b5 89 [2] ba 93 [2] a4 8e [2] a6 8f [2] bd 89 [2] a1 8e [2] bd a1 }

  condition:
    any of them
}