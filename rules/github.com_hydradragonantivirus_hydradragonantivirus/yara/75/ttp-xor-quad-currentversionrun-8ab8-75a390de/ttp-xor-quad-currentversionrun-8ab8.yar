rule TTP_XOR_QUAD_CurrentVersionRun_8ab8 {
  strings:
    $key_8ab8 = { d9 d7 [2] fd d9 [2] d6 f5 [2] f8 d7 [2] ec cc [2] e3 d6 [2] fd cb [2] ff ca [2] e4 cc [2] f8 cb [2] e4 e4 }

  condition:
    any of them
}