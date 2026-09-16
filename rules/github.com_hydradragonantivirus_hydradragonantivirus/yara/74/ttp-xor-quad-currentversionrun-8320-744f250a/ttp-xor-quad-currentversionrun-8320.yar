rule TTP_XOR_QUAD_CurrentVersionRun_8320 {
  strings:
    $key_8320 = { d0 4f [2] f4 41 [2] df 6d [2] f1 4f [2] e5 54 [2] ea 4e [2] f4 53 [2] f6 52 [2] ed 54 [2] f1 53 [2] ed 7c }

  condition:
    any of them
}