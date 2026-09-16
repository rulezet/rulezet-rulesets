rule TTP_XOR_QUAD_CurrentVersionRun_96c1 {
  strings:
    $key_96c1 = { c5 ae [2] e1 a0 [2] ca 8c [2] e4 ae [2] f0 b5 [2] ff af [2] e1 b2 [2] e3 b3 [2] f8 b5 [2] e4 b2 [2] f8 9d }

  condition:
    any of them
}