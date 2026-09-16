rule TTP_XOR_QUAD_CurrentVersionRun_842a {
  strings:
    $key_842a = { d7 45 [2] f3 4b [2] d8 67 [2] f6 45 [2] e2 5e [2] ed 44 [2] f3 59 [2] f1 58 [2] ea 5e [2] f6 59 [2] ea 76 }

  condition:
    any of them
}