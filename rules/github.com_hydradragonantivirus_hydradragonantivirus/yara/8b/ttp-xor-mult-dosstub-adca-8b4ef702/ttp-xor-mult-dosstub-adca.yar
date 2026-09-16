rule TTP_XOR_MULT_DOSStub_adca {
  strings:
    $key_adca = { f9 a2 [2] 8d ba [2] ca b8 [2] 8d a9 [2] c3 a5 [2] cf af [2] d8 a4 [2] c3 ea [2] fe }

  condition:
    any of them
}