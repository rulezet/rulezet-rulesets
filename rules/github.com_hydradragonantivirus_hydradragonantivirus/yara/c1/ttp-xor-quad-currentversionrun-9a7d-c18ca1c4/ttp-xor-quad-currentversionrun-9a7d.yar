rule TTP_XOR_QUAD_CurrentVersionRun_9a7d {
  strings:
    $key_9a7d = { c9 12 [2] ed 1c [2] c6 30 [2] e8 12 [2] fc 09 [2] f3 13 [2] ed 0e [2] ef 0f [2] f4 09 [2] e8 0e [2] f4 21 }

  condition:
    any of them
}