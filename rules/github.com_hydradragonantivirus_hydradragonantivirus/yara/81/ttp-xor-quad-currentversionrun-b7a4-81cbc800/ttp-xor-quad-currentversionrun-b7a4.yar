rule TTP_XOR_QUAD_CurrentVersionRun_b7a4 {
  strings:
    $key_b7a4 = { e4 cb [2] c0 c5 [2] eb e9 [2] c5 cb [2] d1 d0 [2] de ca [2] c0 d7 [2] c2 d6 [2] d9 d0 [2] c5 d7 [2] d9 f8 }

  condition:
    any of them
}