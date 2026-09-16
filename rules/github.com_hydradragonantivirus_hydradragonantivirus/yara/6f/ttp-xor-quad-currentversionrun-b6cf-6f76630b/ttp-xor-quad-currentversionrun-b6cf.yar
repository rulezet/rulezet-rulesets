rule TTP_XOR_QUAD_CurrentVersionRun_b6cf {
  strings:
    $key_b6cf = { e5 a0 [2] c1 ae [2] ea 82 [2] c4 a0 [2] d0 bb [2] df a1 [2] c1 bc [2] c3 bd [2] d8 bb [2] c4 bc [2] d8 93 }

  condition:
    any of them
}