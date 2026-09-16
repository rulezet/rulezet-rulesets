rule TTP_XOR_MULT_DOSStub_a573 {
  strings:
    $key_a573 = { f1 1b [2] 85 03 [2] c2 01 [2] 85 10 [2] cb 1c [2] c7 16 [2] d0 1d [2] cb 53 [2] f6 }

  condition:
    any of them
}