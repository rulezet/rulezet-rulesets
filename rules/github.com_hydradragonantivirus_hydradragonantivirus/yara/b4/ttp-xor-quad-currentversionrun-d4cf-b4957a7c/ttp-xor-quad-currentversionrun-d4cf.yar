rule TTP_XOR_QUAD_CurrentVersionRun_d4cf {
  strings:
    $key_d4cf = { 87 a0 [2] a3 ae [2] 88 82 [2] a6 a0 [2] b2 bb [2] bd a1 [2] a3 bc [2] a1 bd [2] ba bb [2] a6 bc [2] ba 93 }

  condition:
    any of them
}