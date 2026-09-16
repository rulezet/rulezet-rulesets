rule TTP_XOR_MULT_DOSStub_adc9 {
  strings:
    $key_adc9 = { f9 a1 [2] 8d b9 [2] ca bb [2] 8d aa [2] c3 a6 [2] cf ac [2] d8 a7 [2] c3 e9 [2] fe }

  condition:
    any of them
}