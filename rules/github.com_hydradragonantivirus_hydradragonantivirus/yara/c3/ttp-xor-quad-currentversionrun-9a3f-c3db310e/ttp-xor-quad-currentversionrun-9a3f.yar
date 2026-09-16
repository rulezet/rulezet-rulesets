rule TTP_XOR_QUAD_CurrentVersionRun_9a3f {
  strings:
    $key_9a3f = { c9 50 [2] ed 5e [2] c6 72 [2] e8 50 [2] fc 4b [2] f3 51 [2] ed 4c [2] ef 4d [2] f4 4b [2] e8 4c [2] f4 63 }

  condition:
    any of them
}