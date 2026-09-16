rule TTP_XOR_QUAD_CurrentVersionRun_8bc8 {
  strings:
    $key_8bc8 = { d8 a7 [2] fc a9 [2] d7 85 [2] f9 a7 [2] ed bc [2] e2 a6 [2] fc bb [2] fe ba [2] e5 bc [2] f9 bb [2] e5 94 }

  condition:
    any of them
}