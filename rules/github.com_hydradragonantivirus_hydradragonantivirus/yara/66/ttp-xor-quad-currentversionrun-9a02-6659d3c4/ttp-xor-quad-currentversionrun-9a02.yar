rule TTP_XOR_QUAD_CurrentVersionRun_9a02 {
  strings:
    $key_9a02 = { c9 6d [2] ed 63 [2] c6 4f [2] e8 6d [2] fc 76 [2] f3 6c [2] ed 71 [2] ef 70 [2] f4 76 [2] e8 71 [2] f4 5e }

  condition:
    any of them
}