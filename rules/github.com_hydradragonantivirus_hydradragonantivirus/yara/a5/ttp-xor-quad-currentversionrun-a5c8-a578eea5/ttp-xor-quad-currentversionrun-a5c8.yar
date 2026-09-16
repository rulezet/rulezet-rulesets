rule TTP_XOR_QUAD_CurrentVersionRun_a5c8 {
  strings:
    $key_a5c8 = { f6 a7 [2] d2 a9 [2] f9 85 [2] d7 a7 [2] c3 bc [2] cc a6 [2] d2 bb [2] d0 ba [2] cb bc [2] d7 bb [2] cb 94 }

  condition:
    any of them
}