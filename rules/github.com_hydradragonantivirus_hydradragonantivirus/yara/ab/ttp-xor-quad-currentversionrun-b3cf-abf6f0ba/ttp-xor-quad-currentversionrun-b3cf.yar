rule TTP_XOR_QUAD_CurrentVersionRun_b3cf {
  strings:
    $key_b3cf = { e0 a0 [2] c4 ae [2] ef 82 [2] c1 a0 [2] d5 bb [2] da a1 [2] c4 bc [2] c6 bd [2] dd bb [2] c1 bc [2] dd 93 }

  condition:
    any of them
}