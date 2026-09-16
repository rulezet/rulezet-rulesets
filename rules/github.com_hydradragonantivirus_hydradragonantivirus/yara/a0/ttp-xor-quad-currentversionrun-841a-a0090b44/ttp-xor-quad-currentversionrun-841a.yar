rule TTP_XOR_QUAD_CurrentVersionRun_841a {
  strings:
    $key_841a = { d7 75 [2] f3 7b [2] d8 57 [2] f6 75 [2] e2 6e [2] ed 74 [2] f3 69 [2] f1 68 [2] ea 6e [2] f6 69 [2] ea 46 }

  condition:
    any of them
}