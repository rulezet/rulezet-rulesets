rule TTP_XOR_QUAD_CurrentVersionRun_9a29 {
  strings:
    $key_9a29 = { c9 46 [2] ed 48 [2] c6 64 [2] e8 46 [2] fc 5d [2] f3 47 [2] ed 5a [2] ef 5b [2] f4 5d [2] e8 5a [2] f4 75 }

  condition:
    any of them
}