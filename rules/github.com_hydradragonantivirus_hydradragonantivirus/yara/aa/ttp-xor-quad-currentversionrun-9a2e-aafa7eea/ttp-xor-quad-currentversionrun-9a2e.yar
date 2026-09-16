rule TTP_XOR_QUAD_CurrentVersionRun_9a2e {
  strings:
    $key_9a2e = { c9 41 [2] ed 4f [2] c6 63 [2] e8 41 [2] fc 5a [2] f3 40 [2] ed 5d [2] ef 5c [2] f4 5a [2] e8 5d [2] f4 72 }

  condition:
    any of them
}