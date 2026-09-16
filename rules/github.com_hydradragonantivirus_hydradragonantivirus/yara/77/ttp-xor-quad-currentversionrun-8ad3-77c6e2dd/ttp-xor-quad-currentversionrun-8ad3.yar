rule TTP_XOR_QUAD_CurrentVersionRun_8ad3 {
  strings:
    $key_8ad3 = { d9 bc [2] fd b2 [2] d6 9e [2] f8 bc [2] ec a7 [2] e3 bd [2] fd a0 [2] ff a1 [2] e4 a7 [2] f8 a0 [2] e4 8f }

  condition:
    any of them
}