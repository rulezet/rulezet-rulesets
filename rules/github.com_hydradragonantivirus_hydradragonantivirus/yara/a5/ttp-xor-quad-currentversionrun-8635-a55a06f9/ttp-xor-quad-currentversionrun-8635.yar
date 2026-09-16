rule TTP_XOR_QUAD_CurrentVersionRun_8635 {
  strings:
    $key_8635 = { d5 5a [2] f1 54 [2] da 78 [2] f4 5a [2] e0 41 [2] ef 5b [2] f1 46 [2] f3 47 [2] e8 41 [2] f4 46 [2] e8 69 }

  condition:
    any of them
}