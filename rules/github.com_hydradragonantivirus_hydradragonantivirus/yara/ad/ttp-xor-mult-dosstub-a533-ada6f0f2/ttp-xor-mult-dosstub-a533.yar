rule TTP_XOR_MULT_DOSStub_a533 {
  strings:
    $key_a533 = { f1 5b [2] 85 43 [2] c2 41 [2] 85 50 [2] cb 5c [2] c7 56 [2] d0 5d [2] cb 13 [2] f6 }

  condition:
    any of them
}