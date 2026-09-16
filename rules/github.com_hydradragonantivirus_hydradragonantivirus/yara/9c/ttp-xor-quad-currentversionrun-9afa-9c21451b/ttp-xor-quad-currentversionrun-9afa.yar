rule TTP_XOR_QUAD_CurrentVersionRun_9afa {
  strings:
    $key_9afa = { c9 95 [2] ed 9b [2] c6 b7 [2] e8 95 [2] fc 8e [2] f3 94 [2] ed 89 [2] ef 88 [2] f4 8e [2] e8 89 [2] f4 a6 }

  condition:
    any of them
}