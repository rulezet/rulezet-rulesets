rule TTP_XOR_QUAD_CurrentVersionRun_8460 {
  strings:
    $key_8460 = { d7 0f [2] f3 01 [2] d8 2d [2] f6 0f [2] e2 14 [2] ed 0e [2] f3 13 [2] f1 12 [2] ea 14 [2] f6 13 [2] ea 3c }

  condition:
    any of them
}