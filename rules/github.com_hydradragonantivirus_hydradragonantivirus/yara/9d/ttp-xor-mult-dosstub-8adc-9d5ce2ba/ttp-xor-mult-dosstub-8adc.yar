rule TTP_XOR_MULT_DOSStub_8adc {
  strings:
    $key_8adc = { de b4 [2] aa ac [2] ed ae [2] aa bf [2] e4 b3 [2] e8 b9 [2] ff b2 [2] e4 fc [2] d9 }

  condition:
    any of them
}