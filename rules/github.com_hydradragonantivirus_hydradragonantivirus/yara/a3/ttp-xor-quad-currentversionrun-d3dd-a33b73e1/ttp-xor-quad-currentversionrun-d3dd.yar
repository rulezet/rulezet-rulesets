rule TTP_XOR_QUAD_CurrentVersionRun_d3dd {
  strings:
    $key_d3dd = { 80 b2 [2] a4 bc [2] 8f 90 [2] a1 b2 [2] b5 a9 [2] ba b3 [2] a4 ae [2] a6 af [2] bd a9 [2] a1 ae [2] bd 81 }

  condition:
    any of them
}