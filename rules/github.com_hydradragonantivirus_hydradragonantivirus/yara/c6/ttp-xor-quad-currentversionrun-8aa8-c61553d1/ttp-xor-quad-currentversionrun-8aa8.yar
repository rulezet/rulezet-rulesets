rule TTP_XOR_QUAD_CurrentVersionRun_8aa8 {
  strings:
    $key_8aa8 = { d9 c7 [2] fd c9 [2] d6 e5 [2] f8 c7 [2] ec dc [2] e3 c6 [2] fd db [2] ff da [2] e4 dc [2] f8 db [2] e4 f4 }

  condition:
    any of them
}