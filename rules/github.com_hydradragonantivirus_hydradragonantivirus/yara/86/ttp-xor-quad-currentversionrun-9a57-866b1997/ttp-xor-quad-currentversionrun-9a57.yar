rule TTP_XOR_QUAD_CurrentVersionRun_9a57 {
  strings:
    $key_9a57 = { c9 38 [2] ed 36 [2] c6 1a [2] e8 38 [2] fc 23 [2] f3 39 [2] ed 24 [2] ef 25 [2] f4 23 [2] e8 24 [2] f4 0b }

  condition:
    any of them
}