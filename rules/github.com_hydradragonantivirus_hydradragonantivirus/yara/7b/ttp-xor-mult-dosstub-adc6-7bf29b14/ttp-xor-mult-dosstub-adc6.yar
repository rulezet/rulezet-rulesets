rule TTP_XOR_MULT_DOSStub_adc6 {
  strings:
    $key_adc6 = { f9 ae [2] 8d b6 [2] ca b4 [2] 8d a5 [2] c3 a9 [2] cf a3 [2] d8 a8 [2] c3 e6 [2] fe }

  condition:
    any of them
}