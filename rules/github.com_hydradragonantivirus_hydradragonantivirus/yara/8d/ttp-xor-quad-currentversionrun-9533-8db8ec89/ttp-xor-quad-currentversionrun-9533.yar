rule TTP_XOR_QUAD_CurrentVersionRun_9533 {
  strings:
    $key_9533 = { c6 5c [2] e2 52 [2] c9 7e [2] e7 5c [2] f3 47 [2] fc 5d [2] e2 40 [2] e0 41 [2] fb 47 [2] e7 40 [2] fb 6f }

  condition:
    any of them
}