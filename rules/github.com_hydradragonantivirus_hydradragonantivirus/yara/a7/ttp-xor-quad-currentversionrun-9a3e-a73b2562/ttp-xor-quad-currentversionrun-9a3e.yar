rule TTP_XOR_QUAD_CurrentVersionRun_9a3e {
  strings:
    $key_9a3e = { c9 51 [2] ed 5f [2] c6 73 [2] e8 51 [2] fc 4a [2] f3 50 [2] ed 4d [2] ef 4c [2] f4 4a [2] e8 4d [2] f4 62 }

  condition:
    any of them
}