rule TTP_XOR_MULT_DOSStub_a1cb {
  strings:
    $key_a1cb = { f5 a3 [2] 81 bb [2] c6 b9 [2] 81 a8 [2] cf a4 [2] c3 ae [2] d4 a5 [2] cf eb [2] f2 }

  condition:
    any of them
}