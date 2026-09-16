rule TTP_XOR_QUAD_CurrentVersionRun_8aba {
  strings:
    $key_8aba = { d9 d5 [2] fd db [2] d6 f7 [2] f8 d5 [2] ec ce [2] e3 d4 [2] fd c9 [2] ff c8 [2] e4 ce [2] f8 c9 [2] e4 e6 }

  condition:
    any of them
}