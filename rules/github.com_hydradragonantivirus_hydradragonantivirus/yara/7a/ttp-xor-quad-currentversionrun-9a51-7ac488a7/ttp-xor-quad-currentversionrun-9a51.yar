rule TTP_XOR_QUAD_CurrentVersionRun_9a51 {
  strings:
    $key_9a51 = { c9 3e [2] ed 30 [2] c6 1c [2] e8 3e [2] fc 25 [2] f3 3f [2] ed 22 [2] ef 23 [2] f4 25 [2] e8 22 [2] f4 0d }

  condition:
    any of them
}