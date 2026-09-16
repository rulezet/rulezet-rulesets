rule TTP_XOR_QUAD_CurrentVersionRun_8bd4 {
  strings:
    $key_8bd4 = { d8 bb [2] fc b5 [2] d7 99 [2] f9 bb [2] ed a0 [2] e2 ba [2] fc a7 [2] fe a6 [2] e5 a0 [2] f9 a7 [2] e5 88 }

  condition:
    any of them
}