rule TTP_XOR_MULT_DOSStub_31cb {
  strings:
    $key_31cb = { 65 a3 [2] 11 bb [2] 56 b9 [2] 11 a8 [2] 5f a4 [2] 53 ae [2] 44 a5 [2] 5f eb [2] 62 }

  condition:
    any of them
}