rule TTP_XOR_QUAD_CurrentVersionRun_2a57 {
  strings:
    $key_2a57 = { 79 38 [2] 5d 36 [2] 76 1a [2] 58 38 [2] 4c 23 [2] 43 39 [2] 5d 24 [2] 5f 25 [2] 44 23 [2] 58 24 [2] 44 0b }

  condition:
    any of them
}