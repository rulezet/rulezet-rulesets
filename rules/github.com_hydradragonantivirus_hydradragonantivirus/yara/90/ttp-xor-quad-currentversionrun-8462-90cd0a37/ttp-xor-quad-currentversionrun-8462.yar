rule TTP_XOR_QUAD_CurrentVersionRun_8462 {
  strings:
    $key_8462 = { d7 0d [2] f3 03 [2] d8 2f [2] f6 0d [2] e2 16 [2] ed 0c [2] f3 11 [2] f1 10 [2] ea 16 [2] f6 11 [2] ea 3e }

  condition:
    any of them
}