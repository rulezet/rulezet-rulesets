rule TTP_XOR_QUAD_CurrentVersionRun_8313 {
  strings:
    $key_8313 = { d0 7c [2] f4 72 [2] df 5e [2] f1 7c [2] e5 67 [2] ea 7d [2] f4 60 [2] f6 61 [2] ed 67 [2] f1 60 [2] ed 4f }

  condition:
    any of them
}