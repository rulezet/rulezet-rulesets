rule TTP_XOR_QUAD_CurrentVersionRun_26c8 {
  strings:
    $key_26c8 = { 75 a7 [2] 51 a9 [2] 7a 85 [2] 54 a7 [2] 40 bc [2] 4f a6 [2] 51 bb [2] 53 ba [2] 48 bc [2] 54 bb [2] 48 94 }

  condition:
    any of them
}