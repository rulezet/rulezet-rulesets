rule TTP_XOR_QUAD_CurrentVersionRun_83ce {
  strings:
    $key_83ce = { d0 a1 [2] f4 af [2] df 83 [2] f1 a1 [2] e5 ba [2] ea a0 [2] f4 bd [2] f6 bc [2] ed ba [2] f1 bd [2] ed 92 }

  condition:
    any of them
}