rule TTP_XOR_MULT_DOSStub_67cb {
  strings:
    $key_67cb = { 33 a3 [2] 47 bb [2] 00 b9 [2] 47 a8 [2] 09 a4 [2] 05 ae [2] 12 a5 [2] 09 eb [2] 34 }

  condition:
    any of them
}