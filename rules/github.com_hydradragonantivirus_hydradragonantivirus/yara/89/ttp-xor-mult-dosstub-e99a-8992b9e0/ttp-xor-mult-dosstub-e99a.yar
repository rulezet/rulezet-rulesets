rule TTP_XOR_MULT_DOSStub_e99a {
  strings:
    $key_e99a = { bd f2 [2] c9 ea [2] 8e e8 [2] c9 f9 [2] 87 f5 [2] 8b ff [2] 9c f4 [2] 87 ba [2] ba }

  condition:
    any of them
}