rule TTP_XOR_QUAD_CurrentVersionRun_b6c8 {
  strings:
    $key_b6c8 = { e5 a7 [2] c1 a9 [2] ea 85 [2] c4 a7 [2] d0 bc [2] df a6 [2] c1 bb [2] c3 ba [2] d8 bc [2] c4 bb [2] d8 94 }

  condition:
    any of them
}