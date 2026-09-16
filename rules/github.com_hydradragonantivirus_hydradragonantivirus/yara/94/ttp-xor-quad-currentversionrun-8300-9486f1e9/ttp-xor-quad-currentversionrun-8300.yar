rule TTP_XOR_QUAD_CurrentVersionRun_8300 {
  strings:
    $key_8300 = { d0 6f [2] f4 61 [2] df 4d [2] f1 6f [2] e5 74 [2] ea 6e [2] f4 73 [2] f6 72 [2] ed 74 [2] f1 73 [2] ed 5c }

  condition:
    any of them
}