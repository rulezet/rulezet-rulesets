rule TTP_XOR_MULT_DOSStub_ad80 {
  strings:
    $key_ad80 = { f9 e8 [2] 8d f0 [2] ca f2 [2] 8d e3 [2] c3 ef [2] cf e5 [2] d8 ee [2] c3 a0 [2] fe }

  condition:
    any of them
}