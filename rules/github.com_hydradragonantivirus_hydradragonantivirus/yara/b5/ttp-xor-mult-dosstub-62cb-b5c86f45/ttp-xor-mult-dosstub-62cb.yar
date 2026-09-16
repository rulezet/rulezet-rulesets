rule TTP_XOR_MULT_DOSStub_62cb {
  strings:
    $key_62cb = { 36 a3 [2] 42 bb [2] 05 b9 [2] 42 a8 [2] 0c a4 [2] 00 ae [2] 17 a5 [2] 0c eb [2] 31 }

  condition:
    any of them
}