rule TTP_XOR_MULT_DOSStub_adc7 {
  strings:
    $key_adc7 = { f9 af [2] 8d b7 [2] ca b5 [2] 8d a4 [2] c3 a8 [2] cf a2 [2] d8 a9 [2] c3 e7 [2] fe }

  condition:
    any of them
}