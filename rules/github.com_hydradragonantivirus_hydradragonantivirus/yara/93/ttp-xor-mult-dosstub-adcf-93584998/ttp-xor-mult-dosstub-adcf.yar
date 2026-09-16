rule TTP_XOR_MULT_DOSStub_adcf {
  strings:
    $key_adcf = { f9 a7 [2] 8d bf [2] ca bd [2] 8d ac [2] c3 a0 [2] cf aa [2] d8 a1 [2] c3 ef [2] fe }

  condition:
    any of them
}