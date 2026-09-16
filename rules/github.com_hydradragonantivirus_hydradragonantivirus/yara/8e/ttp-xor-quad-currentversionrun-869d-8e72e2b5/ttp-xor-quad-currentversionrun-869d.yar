rule TTP_XOR_QUAD_CurrentVersionRun_869d {
  strings:
    $key_869d = { d5 f2 [2] f1 fc [2] da d0 [2] f4 f2 [2] e0 e9 [2] ef f3 [2] f1 ee [2] f3 ef [2] e8 e9 [2] f4 ee [2] e8 c1 }

  condition:
    any of them
}