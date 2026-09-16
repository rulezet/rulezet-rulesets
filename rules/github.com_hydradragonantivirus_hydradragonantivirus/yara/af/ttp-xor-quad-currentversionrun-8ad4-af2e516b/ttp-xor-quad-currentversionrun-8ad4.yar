rule TTP_XOR_QUAD_CurrentVersionRun_8ad4 {
  strings:
    $key_8ad4 = { d9 bb [2] fd b5 [2] d6 99 [2] f8 bb [2] ec a0 [2] e3 ba [2] fd a7 [2] ff a6 [2] e4 a0 [2] f8 a7 [2] e4 88 }

  condition:
    any of them
}