rule TTP_XOR_QUAD_CurrentVersionRun_8a57 {
  strings:
    $key_8a57 = { d9 38 [2] fd 36 [2] d6 1a [2] f8 38 [2] ec 23 [2] e3 39 [2] fd 24 [2] ff 25 [2] e4 23 [2] f8 24 [2] e4 0b }

  condition:
    any of them
}