rule TTP_XOR_QUAD_CurrentVersionRun_9a7f {
  strings:
    $key_9a7f = { c9 10 [2] ed 1e [2] c6 32 [2] e8 10 [2] fc 0b [2] f3 11 [2] ed 0c [2] ef 0d [2] f4 0b [2] e8 0c [2] f4 23 }

  condition:
    any of them
}