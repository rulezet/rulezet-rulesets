rule TTP_XOR_QUAD_CurrentVersionRun_8ab4 {
  strings:
    $key_8ab4 = { d9 db [2] fd d5 [2] d6 f9 [2] f8 db [2] ec c0 [2] e3 da [2] fd c7 [2] ff c6 [2] e4 c0 [2] f8 c7 [2] e4 e8 }

  condition:
    any of them
}