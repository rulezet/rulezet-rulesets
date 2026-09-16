rule TTP_XOR_QUAD_CurrentVersionRun_8ec9 {
  strings:
    $key_8ec9 = { dd a6 [2] f9 a8 [2] d2 84 [2] fc a6 [2] e8 bd [2] e7 a7 [2] f9 ba [2] fb bb [2] e0 bd [2] fc ba [2] e0 95 }

  condition:
    any of them
}