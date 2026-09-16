rule TTP_XOR_QUAD_CurrentVersionRun_9a16 {
  strings:
    $key_9a16 = { c9 79 [2] ed 77 [2] c6 5b [2] e8 79 [2] fc 62 [2] f3 78 [2] ed 65 [2] ef 64 [2] f4 62 [2] e8 65 [2] f4 4a }

  condition:
    any of them
}