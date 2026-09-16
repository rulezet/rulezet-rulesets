rule TTP_XOR_QUAD_CurrentVersionRun_96db {
  strings:
    $key_96db = { c5 b4 [2] e1 ba [2] ca 96 [2] e4 b4 [2] f0 af [2] ff b5 [2] e1 a8 [2] e3 a9 [2] f8 af [2] e4 a8 [2] f8 87 }

  condition:
    any of them
}