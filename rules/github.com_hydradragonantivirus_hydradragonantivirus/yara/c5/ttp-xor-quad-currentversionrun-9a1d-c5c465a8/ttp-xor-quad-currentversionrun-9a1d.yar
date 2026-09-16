rule TTP_XOR_QUAD_CurrentVersionRun_9a1d {
  strings:
    $key_9a1d = { c9 72 [2] ed 7c [2] c6 50 [2] e8 72 [2] fc 69 [2] f3 73 [2] ed 6e [2] ef 6f [2] f4 69 [2] e8 6e [2] f4 41 }

  condition:
    any of them
}