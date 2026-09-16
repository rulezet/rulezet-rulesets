rule TTP_XOR_QUAD_CurrentVersionRun_8aa4 {
  strings:
    $key_8aa4 = { d9 cb [2] fd c5 [2] d6 e9 [2] f8 cb [2] ec d0 [2] e3 ca [2] fd d7 [2] ff d6 [2] e4 d0 [2] f8 d7 [2] e4 f8 }

  condition:
    any of them
}