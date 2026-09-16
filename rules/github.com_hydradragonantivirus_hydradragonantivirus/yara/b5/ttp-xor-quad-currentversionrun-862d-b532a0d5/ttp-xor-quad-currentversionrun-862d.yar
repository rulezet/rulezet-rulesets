rule TTP_XOR_QUAD_CurrentVersionRun_862d {
  strings:
    $key_862d = { d5 42 [2] f1 4c [2] da 60 [2] f4 42 [2] e0 59 [2] ef 43 [2] f1 5e [2] f3 5f [2] e8 59 [2] f4 5e [2] e8 71 }

  condition:
    any of them
}