rule TTP_XOR_QUAD_CurrentVersionRun_9a6d {
  strings:
    $key_9a6d = { c9 02 [2] ed 0c [2] c6 20 [2] e8 02 [2] fc 19 [2] f3 03 [2] ed 1e [2] ef 1f [2] f4 19 [2] e8 1e [2] f4 31 }

  condition:
    any of them
}