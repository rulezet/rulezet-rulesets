rule TTP_XOR_QUAD_CurrentVersionRun_a57e {
  strings:
    $key_a57e = { f6 11 [2] d2 1f [2] f9 33 [2] d7 11 [2] c3 0a [2] cc 10 [2] d2 0d [2] d0 0c [2] cb 0a [2] d7 0d [2] cb 22 }

  condition:
    any of them
}