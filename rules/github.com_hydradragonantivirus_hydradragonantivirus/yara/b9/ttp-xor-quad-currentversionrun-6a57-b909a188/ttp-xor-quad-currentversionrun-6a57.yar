rule TTP_XOR_QUAD_CurrentVersionRun_6a57 {
  strings:
    $key_6a57 = { 39 38 [2] 1d 36 [2] 36 1a [2] 18 38 [2] 0c 23 [2] 03 39 [2] 1d 24 [2] 1f 25 [2] 04 23 [2] 18 24 [2] 04 0b }

  condition:
    any of them
}