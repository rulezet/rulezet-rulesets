rule TTP_XOR_MULT_DOSStub_ad81 {
  strings:
    $key_ad81 = { f9 e9 [2] 8d f1 [2] ca f3 [2] 8d e2 [2] c3 ee [2] cf e4 [2] d8 ef [2] c3 a1 [2] fe }

  condition:
    any of them
}