rule TTP_XOR_QUAD_CurrentVersionRun_8420 {
  strings:
    $key_8420 = { d7 4f [2] f3 41 [2] d8 6d [2] f6 4f [2] e2 54 [2] ed 4e [2] f3 53 [2] f1 52 [2] ea 54 [2] f6 53 [2] ea 7c }

  condition:
    any of them
}