rule TTP_XOR_QUAD_CurrentVersionRun_9a50 {
  strings:
    $key_9a50 = { c9 3f [2] ed 31 [2] c6 1d [2] e8 3f [2] fc 24 [2] f3 3e [2] ed 23 [2] ef 22 [2] f4 24 [2] e8 23 [2] f4 0c }

  condition:
    any of them
}