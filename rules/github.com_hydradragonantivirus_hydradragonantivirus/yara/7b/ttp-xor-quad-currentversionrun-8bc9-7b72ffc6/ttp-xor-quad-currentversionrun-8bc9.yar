rule TTP_XOR_QUAD_CurrentVersionRun_8bc9 {
  strings:
    $key_8bc9 = { d8 a6 [2] fc a8 [2] d7 84 [2] f9 a6 [2] ed bd [2] e2 a7 [2] fc ba [2] fe bb [2] e5 bd [2] f9 ba [2] e5 95 }

  condition:
    any of them
}