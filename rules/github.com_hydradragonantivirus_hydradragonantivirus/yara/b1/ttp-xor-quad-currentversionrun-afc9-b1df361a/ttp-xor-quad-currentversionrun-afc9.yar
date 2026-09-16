rule TTP_XOR_QUAD_CurrentVersionRun_afc9 {
  strings:
    $key_afc9 = { fc a6 [2] d8 a8 [2] f3 84 [2] dd a6 [2] c9 bd [2] c6 a7 [2] d8 ba [2] da bb [2] c1 bd [2] dd ba [2] c1 95 }

  condition:
    any of them
}