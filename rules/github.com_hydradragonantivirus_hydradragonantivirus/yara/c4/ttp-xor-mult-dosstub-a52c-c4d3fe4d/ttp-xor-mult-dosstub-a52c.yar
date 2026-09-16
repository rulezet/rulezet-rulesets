rule TTP_XOR_MULT_DOSStub_a52c {
  strings:
    $key_a52c = { f1 44 [2] 85 5c [2] c2 5e [2] 85 4f [2] cb 43 [2] c7 49 [2] d0 42 [2] cb 0c [2] f6 }

  condition:
    any of them
}