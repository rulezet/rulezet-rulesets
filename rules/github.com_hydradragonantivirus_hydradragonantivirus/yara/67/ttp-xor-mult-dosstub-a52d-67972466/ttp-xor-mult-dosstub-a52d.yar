rule TTP_XOR_MULT_DOSStub_a52d {
  strings:
    $key_a52d = { f1 45 [2] 85 5d [2] c2 5f [2] 85 4e [2] cb 42 [2] c7 48 [2] d0 43 [2] cb 0d [2] f6 }

  condition:
    any of them
}