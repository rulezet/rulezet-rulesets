rule TTP_XOR_QUAD_CurrentVersionRun_9a4e {
  strings:
    $key_9a4e = { c9 21 [2] ed 2f [2] c6 03 [2] e8 21 [2] fc 3a [2] f3 20 [2] ed 3d [2] ef 3c [2] f4 3a [2] e8 3d [2] f4 12 }

  condition:
    any of them
}