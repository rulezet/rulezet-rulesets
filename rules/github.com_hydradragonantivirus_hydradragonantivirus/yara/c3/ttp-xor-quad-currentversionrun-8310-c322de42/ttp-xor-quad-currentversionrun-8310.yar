rule TTP_XOR_QUAD_CurrentVersionRun_8310 {
  strings:
    $key_8310 = { d0 7f [2] f4 71 [2] df 5d [2] f1 7f [2] e5 64 [2] ea 7e [2] f4 63 [2] f6 62 [2] ed 64 [2] f1 63 [2] ed 4c }

  condition:
    any of them
}