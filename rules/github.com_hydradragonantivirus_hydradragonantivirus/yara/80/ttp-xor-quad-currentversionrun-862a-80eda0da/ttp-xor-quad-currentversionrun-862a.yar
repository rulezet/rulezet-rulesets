rule TTP_XOR_QUAD_CurrentVersionRun_862a {
  strings:
    $key_862a = { d5 45 [2] f1 4b [2] da 67 [2] f4 45 [2] e0 5e [2] ef 44 [2] f1 59 [2] f3 58 [2] e8 5e [2] f4 59 [2] e8 76 }

  condition:
    any of them
}