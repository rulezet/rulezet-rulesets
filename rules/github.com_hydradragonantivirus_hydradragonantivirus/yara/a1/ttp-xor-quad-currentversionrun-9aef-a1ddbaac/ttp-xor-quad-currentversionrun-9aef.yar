rule TTP_XOR_QUAD_CurrentVersionRun_9aef {
  strings:
    $key_9aef = { c9 80 [2] ed 8e [2] c6 a2 [2] e8 80 [2] fc 9b [2] f3 81 [2] ed 9c [2] ef 9d [2] f4 9b [2] e8 9c [2] f4 b3 }

  condition:
    any of them
}