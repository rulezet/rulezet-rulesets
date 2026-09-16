rule TTP_XOR_MULT_DOSStub_a8d4 {
  strings:
    $key_a8d4 = { fc bc [2] 88 a4 [2] cf a6 [2] 88 b7 [2] c6 bb [2] ca b1 [2] dd ba [2] c6 f4 [2] fb }

  condition:
    any of them
}