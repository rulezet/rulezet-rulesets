rule TTP_XOR_QUAD_CurrentVersionRun_8426 {
  strings:
    $key_8426 = { d7 49 [2] f3 47 [2] d8 6b [2] f6 49 [2] e2 52 [2] ed 48 [2] f3 55 [2] f1 54 [2] ea 52 [2] f6 55 [2] ea 7a }

  condition:
    any of them
}