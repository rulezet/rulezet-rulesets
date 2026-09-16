rule TTP_XOR_QUAD_CurrentVersionRun_3a57 {
  strings:
    $key_3a57 = { 69 38 [2] 4d 36 [2] 66 1a [2] 48 38 [2] 5c 23 [2] 53 39 [2] 4d 24 [2] 4f 25 [2] 54 23 [2] 48 24 [2] 54 0b }

  condition:
    any of them
}