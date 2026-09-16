rule TTP_XOR_QUAD_CurrentVersionRun_83e1 {
  strings:
    $key_83e1 = { d0 8e [2] f4 80 [2] df ac [2] f1 8e [2] e5 95 [2] ea 8f [2] f4 92 [2] f6 93 [2] ed 95 [2] f1 92 [2] ed bd }

  condition:
    any of them
}