rule TTP_XOR_QUAD_CurrentVersionRun_9a7a {
  strings:
    $key_9a7a = { c9 15 [2] ed 1b [2] c6 37 [2] e8 15 [2] fc 0e [2] f3 14 [2] ed 09 [2] ef 08 [2] f4 0e [2] e8 09 [2] f4 26 }

  condition:
    any of them
}