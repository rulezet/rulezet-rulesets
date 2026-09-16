rule TTP_XOR_QUAD_CurrentVersionRun_9a3b {
  strings:
    $key_9a3b = { c9 54 [2] ed 5a [2] c6 76 [2] e8 54 [2] fc 4f [2] f3 55 [2] ed 48 [2] ef 49 [2] f4 4f [2] e8 48 [2] f4 67 }

  condition:
    any of them
}