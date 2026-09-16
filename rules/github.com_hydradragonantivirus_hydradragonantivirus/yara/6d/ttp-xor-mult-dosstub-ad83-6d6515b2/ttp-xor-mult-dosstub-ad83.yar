rule TTP_XOR_MULT_DOSStub_ad83 {
  strings:
    $key_ad83 = { f9 eb [2] 8d f3 [2] ca f1 [2] 8d e0 [2] c3 ec [2] cf e6 [2] d8 ed [2] c3 a3 [2] fe }

  condition:
    any of them
}