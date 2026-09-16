rule TTP_XOR_QUAD_CurrentVersionRun_a57a {
  strings:
    $key_a57a = { f6 15 [2] d2 1b [2] f9 37 [2] d7 15 [2] c3 0e [2] cc 14 [2] d2 09 [2] d0 08 [2] cb 0e [2] d7 09 [2] cb 26 }

  condition:
    any of them
}