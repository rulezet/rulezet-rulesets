rule TTP_XOR_QUAD_CurrentVersionRun_d3cf {
  strings:
    $key_d3cf = { 80 a0 [2] a4 ae [2] 8f 82 [2] a1 a0 [2] b5 bb [2] ba a1 [2] a4 bc [2] a6 bd [2] bd bb [2] a1 bc [2] bd 93 }

  condition:
    any of them
}