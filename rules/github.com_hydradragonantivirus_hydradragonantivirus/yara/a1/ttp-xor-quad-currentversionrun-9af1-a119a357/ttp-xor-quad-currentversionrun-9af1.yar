rule TTP_XOR_QUAD_CurrentVersionRun_9af1 {
  strings:
    $key_9af1 = { c9 9e [2] ed 90 [2] c6 bc [2] e8 9e [2] fc 85 [2] f3 9f [2] ed 82 [2] ef 83 [2] f4 85 [2] e8 82 [2] f4 ad }

  condition:
    any of them
}