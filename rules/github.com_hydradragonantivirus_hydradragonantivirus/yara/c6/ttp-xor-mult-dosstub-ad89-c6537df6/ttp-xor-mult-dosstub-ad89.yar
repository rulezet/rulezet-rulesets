rule TTP_XOR_MULT_DOSStub_ad89 {
  strings:
    $key_ad89 = { f9 e1 [2] 8d f9 [2] ca fb [2] 8d ea [2] c3 e6 [2] cf ec [2] d8 e7 [2] c3 a9 [2] fe }

  condition:
    any of them
}