rule TTP_XOR_MULT_DOSStub_77cb {
  strings:
    $key_77cb = { 23 a3 [2] 57 bb [2] 10 b9 [2] 57 a8 [2] 19 a4 [2] 15 ae [2] 02 a5 [2] 19 eb [2] 24 }

  condition:
    any of them
}