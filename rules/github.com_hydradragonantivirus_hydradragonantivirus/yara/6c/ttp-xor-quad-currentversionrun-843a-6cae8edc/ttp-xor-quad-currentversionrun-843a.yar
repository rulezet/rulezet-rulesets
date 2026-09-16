rule TTP_XOR_QUAD_CurrentVersionRun_843a {
  strings:
    $key_843a = { d7 55 [2] f3 5b [2] d8 77 [2] f6 55 [2] e2 4e [2] ed 54 [2] f3 49 [2] f1 48 [2] ea 4e [2] f6 49 [2] ea 66 }

  condition:
    any of them
}