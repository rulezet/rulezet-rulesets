rule TTP_XOR_QUAD_CurrentVersionRun_9a1c {
  strings:
    $key_9a1c = { c9 73 [2] ed 7d [2] c6 51 [2] e8 73 [2] fc 68 [2] f3 72 [2] ed 6f [2] ef 6e [2] f4 68 [2] e8 6f [2] f4 40 }

  condition:
    any of them
}