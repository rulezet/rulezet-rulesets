rule TTP_XOR_MULT_DOSStub_a511 {
  strings:
    $key_a511 = { f1 79 [2] 85 61 [2] c2 63 [2] 85 72 [2] cb 7e [2] c7 74 [2] d0 7f [2] cb 31 [2] f6 }

  condition:
    any of them
}