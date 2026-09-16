rule TTP_XOR_QUAD_CurrentVersionRun_d7cf {
  strings:
    $key_d7cf = { 84 a0 [2] a0 ae [2] 8b 82 [2] a5 a0 [2] b1 bb [2] be a1 [2] a0 bc [2] a2 bd [2] b9 bb [2] a5 bc [2] b9 93 }

  condition:
    any of them
}