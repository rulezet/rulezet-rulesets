rule TTP_XOR_MULT_DOSStub_a53d {
  strings:
    $key_a53d = { f1 55 [2] 85 4d [2] c2 4f [2] 85 5e [2] cb 52 [2] c7 58 [2] d0 53 [2] cb 1d [2] f6 }

  condition:
    any of them
}