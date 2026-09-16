rule TTP_XOR_QUAD_CurrentVersionRun_868a {
  strings:
    $key_868a = { d5 e5 [2] f1 eb [2] da c7 [2] f4 e5 [2] e0 fe [2] ef e4 [2] f1 f9 [2] f3 f8 [2] e8 fe [2] f4 f9 [2] e8 d6 }

  condition:
    any of them
}