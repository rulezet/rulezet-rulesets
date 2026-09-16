rule TTP_XOR_MULT_DOSStub_14cb {
  strings:
    $key_14cb = { 40 a3 [2] 34 bb [2] 73 b9 [2] 34 a8 [2] 7a a4 [2] 76 ae [2] 61 a5 [2] 7a eb [2] 47 }

  condition:
    any of them
}