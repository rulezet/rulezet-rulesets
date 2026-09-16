rule TTP_XOR_MULT_DOSStub_a513 {
  strings:
    $key_a513 = { f1 7b [2] 85 63 [2] c2 61 [2] 85 70 [2] cb 7c [2] c7 76 [2] d0 7d [2] cb 33 [2] f6 }

  condition:
    any of them
}