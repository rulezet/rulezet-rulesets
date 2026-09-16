rule TTP_XOR_MULT_DOSStub_55cb {
  strings:
    $key_55cb = { 01 a3 [2] 75 bb [2] 32 b9 [2] 75 a8 [2] 3b a4 [2] 37 ae [2] 20 a5 [2] 3b eb [2] 06 }

  condition:
    any of them
}