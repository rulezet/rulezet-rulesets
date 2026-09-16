rule TTP_XOR_QUAD_CurrentVersionRun_9237 {
  strings:
    $key_9237 = { c1 58 [2] e5 56 [2] ce 7a [2] e0 58 [2] f4 43 [2] fb 59 [2] e5 44 [2] e7 45 [2] fc 43 [2] e0 44 [2] fc 6b }

  condition:
    any of them
}