rule TTP_XOR_QUAD_CurrentVersionRun_9a3a {
  strings:
    $key_9a3a = { c9 55 [2] ed 5b [2] c6 77 [2] e8 55 [2] fc 4e [2] f3 54 [2] ed 49 [2] ef 48 [2] f4 4e [2] e8 49 [2] f4 66 }

  condition:
    any of them
}