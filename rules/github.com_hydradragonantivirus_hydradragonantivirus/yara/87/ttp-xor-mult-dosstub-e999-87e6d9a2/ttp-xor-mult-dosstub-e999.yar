rule TTP_XOR_MULT_DOSStub_e999 {
  strings:
    $key_e999 = { bd f1 [2] c9 e9 [2] 8e eb [2] c9 fa [2] 87 f6 [2] 8b fc [2] 9c f7 [2] 87 b9 [2] ba }

  condition:
    any of them
}