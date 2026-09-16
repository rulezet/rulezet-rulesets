rule TTP_XOR_MULT_DOSStub_ad86 {
  strings:
    $key_ad86 = { f9 ee [2] 8d f6 [2] ca f4 [2] 8d e5 [2] c3 e9 [2] cf e3 [2] d8 e8 [2] c3 a6 [2] fe }

  condition:
    any of them
}