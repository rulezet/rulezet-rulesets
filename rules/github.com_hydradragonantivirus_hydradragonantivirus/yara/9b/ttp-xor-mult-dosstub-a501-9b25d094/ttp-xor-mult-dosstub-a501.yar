rule TTP_XOR_MULT_DOSStub_a501 {
  strings:
    $key_a501 = { f1 69 [2] 85 71 [2] c2 73 [2] 85 62 [2] cb 6e [2] c7 64 [2] d0 6f [2] cb 21 [2] f6 }

  condition:
    any of them
}