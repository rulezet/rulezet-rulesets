rule TTP_XOR_QUAD_CurrentVersionRun_860d {
  strings:
    $key_860d = { d5 62 [2] f1 6c [2] da 40 [2] f4 62 [2] e0 79 [2] ef 63 [2] f1 7e [2] f3 7f [2] e8 79 [2] f4 7e [2] e8 51 }

  condition:
    any of them
}