rule TTP_XOR_QUAD_CurrentVersionRun_83aa {
  strings:
    $key_83aa = { d0 c5 [2] f4 cb [2] df e7 [2] f1 c5 [2] e5 de [2] ea c4 [2] f4 d9 [2] f6 d8 [2] ed de [2] f1 d9 [2] ed f6 }

  condition:
    any of them
}