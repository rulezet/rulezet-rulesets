rule TTP_XOR_MULT_DOSStub_a510 {
  strings:
    $key_a510 = { f1 78 [2] 85 60 [2] c2 62 [2] 85 73 [2] cb 7f [2] c7 75 [2] d0 7e [2] cb 30 [2] f6 }

  condition:
    any of them
}