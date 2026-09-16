rule TTP_XOR_QUAD_CurrentVersionRun_a57d {
  strings:
    $key_a57d = { f6 12 [2] d2 1c [2] f9 30 [2] d7 12 [2] c3 09 [2] cc 13 [2] d2 0e [2] d0 0f [2] cb 09 [2] d7 0e [2] cb 21 }

  condition:
    any of them
}