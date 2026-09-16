rule TTP_XOR_MULT_DOSStub_ad84 {
  strings:
    $key_ad84 = { f9 ec [2] 8d f4 [2] ca f6 [2] 8d e7 [2] c3 eb [2] cf e1 [2] d8 ea [2] c3 a4 [2] fe }

  condition:
    any of them
}