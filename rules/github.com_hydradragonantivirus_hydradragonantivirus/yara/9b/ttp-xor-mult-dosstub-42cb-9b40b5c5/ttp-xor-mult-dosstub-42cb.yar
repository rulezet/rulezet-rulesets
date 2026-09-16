rule TTP_XOR_MULT_DOSStub_42cb {
  strings:
    $key_42cb = { 16 a3 [2] 62 bb [2] 25 b9 [2] 62 a8 [2] 2c a4 [2] 20 ae [2] 37 a5 [2] 2c eb [2] 11 }

  condition:
    any of them
}