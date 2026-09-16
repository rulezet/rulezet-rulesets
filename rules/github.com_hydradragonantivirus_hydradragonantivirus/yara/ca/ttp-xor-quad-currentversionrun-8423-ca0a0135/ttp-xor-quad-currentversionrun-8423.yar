rule TTP_XOR_QUAD_CurrentVersionRun_8423 {
  strings:
    $key_8423 = { d7 4c [2] f3 42 [2] d8 6e [2] f6 4c [2] e2 57 [2] ed 4d [2] f3 50 [2] f1 51 [2] ea 57 [2] f6 50 [2] ea 7f }

  condition:
    any of them
}