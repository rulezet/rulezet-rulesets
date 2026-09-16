rule TTP_XOR_QUAD_CurrentVersionRun_9a0c {
  strings:
    $key_9a0c = { c9 63 [2] ed 6d [2] c6 41 [2] e8 63 [2] fc 78 [2] f3 62 [2] ed 7f [2] ef 7e [2] f4 78 [2] e8 7f [2] f4 50 }

  condition:
    any of them
}