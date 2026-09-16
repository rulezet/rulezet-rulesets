rule TTP_XOR_QUAD_CurrentVersionRun_0a57 {
  strings:
    $key_0a57 = { 59 38 [2] 7d 36 [2] 56 1a [2] 78 38 [2] 6c 23 [2] 63 39 [2] 7d 24 [2] 7f 25 [2] 64 23 [2] 78 24 [2] 64 0b }

  condition:
    any of them
}