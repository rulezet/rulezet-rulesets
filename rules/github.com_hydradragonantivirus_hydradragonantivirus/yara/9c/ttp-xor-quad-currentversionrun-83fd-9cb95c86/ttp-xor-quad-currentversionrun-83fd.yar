rule TTP_XOR_QUAD_CurrentVersionRun_83fd {
  strings:
    $key_83fd = { d0 92 [2] f4 9c [2] df b0 [2] f1 92 [2] e5 89 [2] ea 93 [2] f4 8e [2] f6 8f [2] ed 89 [2] f1 8e [2] ed a1 }

  condition:
    any of them
}