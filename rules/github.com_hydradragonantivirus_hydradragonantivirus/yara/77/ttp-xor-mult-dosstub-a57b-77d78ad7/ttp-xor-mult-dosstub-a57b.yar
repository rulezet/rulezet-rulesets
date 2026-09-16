rule TTP_XOR_MULT_DOSStub_a57b {
  strings:
    $key_a57b = { f1 13 [2] 85 0b [2] c2 09 [2] 85 18 [2] cb 14 [2] c7 1e [2] d0 15 [2] cb 5b [2] f6 }

  condition:
    any of them
}