rule TTP_XOR_QUAD_CurrentVersionRun_8aa5 {
  strings:
    $key_8aa5 = { d9 ca [2] fd c4 [2] d6 e8 [2] f8 ca [2] ec d1 [2] e3 cb [2] fd d6 [2] ff d7 [2] e4 d1 [2] f8 d6 [2] e4 f9 }

  condition:
    any of them
}