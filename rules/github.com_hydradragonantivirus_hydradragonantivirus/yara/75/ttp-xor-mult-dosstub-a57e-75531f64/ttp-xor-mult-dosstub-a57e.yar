rule TTP_XOR_MULT_DOSStub_a57e {
  strings:
    $key_a57e = { f1 16 [2] 85 0e [2] c2 0c [2] 85 1d [2] cb 11 [2] c7 1b [2] d0 10 [2] cb 5e [2] f6 }

  condition:
    any of them
}