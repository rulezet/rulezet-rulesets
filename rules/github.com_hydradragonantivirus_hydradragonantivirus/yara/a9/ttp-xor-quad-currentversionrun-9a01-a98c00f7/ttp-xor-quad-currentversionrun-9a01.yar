rule TTP_XOR_QUAD_CurrentVersionRun_9a01 {
  strings:
    $key_9a01 = { c9 6e [2] ed 60 [2] c6 4c [2] e8 6e [2] fc 75 [2] f3 6f [2] ed 72 [2] ef 73 [2] f4 75 [2] e8 72 [2] f4 5d }

  condition:
    any of them
}