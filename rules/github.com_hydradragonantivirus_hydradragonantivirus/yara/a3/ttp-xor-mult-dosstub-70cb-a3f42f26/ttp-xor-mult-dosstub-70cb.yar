rule TTP_XOR_MULT_DOSStub_70cb {
  strings:
    $key_70cb = { 24 a3 [2] 50 bb [2] 17 b9 [2] 50 a8 [2] 1e a4 [2] 12 ae [2] 05 a5 [2] 1e eb [2] 23 }

  condition:
    any of them
}