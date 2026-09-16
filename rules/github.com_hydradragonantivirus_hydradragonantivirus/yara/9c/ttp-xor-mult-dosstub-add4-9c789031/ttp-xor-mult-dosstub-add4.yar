rule TTP_XOR_MULT_DOSStub_add4 {
  strings:
    $key_add4 = { f9 bc [2] 8d a4 [2] ca a6 [2] 8d b7 [2] c3 bb [2] cf b1 [2] d8 ba [2] c3 f4 [2] fe }

  condition:
    any of them
}