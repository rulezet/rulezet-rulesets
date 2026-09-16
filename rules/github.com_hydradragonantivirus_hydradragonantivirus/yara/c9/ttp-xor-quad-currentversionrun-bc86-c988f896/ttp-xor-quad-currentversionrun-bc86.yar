rule TTP_XOR_QUAD_CurrentVersionRun_bc86 {
  strings:
    $key_bc86 = { ef e9 [2] cb e7 [2] e0 cb [2] ce e9 [2] da f2 [2] d5 e8 [2] cb f5 [2] c9 f4 [2] d2 f2 [2] ce f5 [2] d2 da }

  condition:
    any of them
}