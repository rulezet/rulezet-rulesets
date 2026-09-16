rule TTP_XOR_QUAD_CurrentVersionRun_96da {
  strings:
    $key_96da = { c5 b5 [2] e1 bb [2] ca 97 [2] e4 b5 [2] f0 ae [2] ff b4 [2] e1 a9 [2] e3 a8 [2] f8 ae [2] e4 a9 [2] f8 86 }

  condition:
    any of them
}