rule TTP_XOR_MULT_DOSStub_07cb {
  strings:
    $key_07cb = { 53 a3 [2] 27 bb [2] 60 b9 [2] 27 a8 [2] 69 a4 [2] 65 ae [2] 72 a5 [2] 69 eb [2] 54 }

  condition:
    any of them
}