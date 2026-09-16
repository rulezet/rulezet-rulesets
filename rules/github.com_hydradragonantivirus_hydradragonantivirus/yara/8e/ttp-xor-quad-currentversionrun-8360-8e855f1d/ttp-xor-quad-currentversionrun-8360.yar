rule TTP_XOR_QUAD_CurrentVersionRun_8360 {
  strings:
    $key_8360 = { d0 0f [2] f4 01 [2] df 2d [2] f1 0f [2] e5 14 [2] ea 0e [2] f4 13 [2] f6 12 [2] ed 14 [2] f1 13 [2] ed 3c }

  condition:
    any of them
}