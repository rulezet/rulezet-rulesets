rule TTP_XOR_QUAD_CurrentVersionRun_4a57 {
  strings:
    $key_4a57 = { 19 38 [2] 3d 36 [2] 16 1a [2] 38 38 [2] 2c 23 [2] 23 39 [2] 3d 24 [2] 3f 25 [2] 24 23 [2] 38 24 [2] 24 0b }

  condition:
    any of them
}