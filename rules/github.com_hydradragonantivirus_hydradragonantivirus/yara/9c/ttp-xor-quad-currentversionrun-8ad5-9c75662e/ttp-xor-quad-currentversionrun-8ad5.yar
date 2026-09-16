rule TTP_XOR_QUAD_CurrentVersionRun_8ad5 {
  strings:
    $key_8ad5 = { d9 ba [2] fd b4 [2] d6 98 [2] f8 ba [2] ec a1 [2] e3 bb [2] fd a6 [2] ff a7 [2] e4 a1 [2] f8 a6 [2] e4 89 }

  condition:
    any of them
}