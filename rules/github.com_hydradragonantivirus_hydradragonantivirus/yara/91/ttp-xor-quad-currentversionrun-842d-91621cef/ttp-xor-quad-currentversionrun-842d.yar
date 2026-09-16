rule TTP_XOR_QUAD_CurrentVersionRun_842d {
  strings:
    $key_842d = { d7 42 [2] f3 4c [2] d8 60 [2] f6 42 [2] e2 59 [2] ed 43 [2] f3 5e [2] f1 5f [2] ea 59 [2] f6 5e [2] ea 71 }

  condition:
    any of them
}