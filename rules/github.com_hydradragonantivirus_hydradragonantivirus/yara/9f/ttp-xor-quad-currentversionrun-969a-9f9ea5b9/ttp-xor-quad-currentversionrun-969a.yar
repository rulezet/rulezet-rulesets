rule TTP_XOR_QUAD_CurrentVersionRun_969a {
  strings:
    $key_969a = { c5 f5 [2] e1 fb [2] ca d7 [2] e4 f5 [2] f0 ee [2] ff f4 [2] e1 e9 [2] e3 e8 [2] f8 ee [2] e4 e9 [2] f8 c6 }

  condition:
    any of them
}