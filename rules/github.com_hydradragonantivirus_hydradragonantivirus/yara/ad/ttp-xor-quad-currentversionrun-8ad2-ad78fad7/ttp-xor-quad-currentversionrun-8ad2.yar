rule TTP_XOR_QUAD_CurrentVersionRun_8ad2 {
  strings:
    $key_8ad2 = { d9 bd [2] fd b3 [2] d6 9f [2] f8 bd [2] ec a6 [2] e3 bc [2] fd a1 [2] ff a0 [2] e4 a6 [2] f8 a1 [2] e4 8e }

  condition:
    any of them
}