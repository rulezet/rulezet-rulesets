rule TTP_XOR_MULT_DOSStub_a5e0 {
  strings:
    $key_a5e0 = { f1 88 [2] 85 90 [2] c2 92 [2] 85 83 [2] cb 8f [2] c7 85 [2] d0 8e [2] cb c0 [2] f6 }

  condition:
    any of them
}