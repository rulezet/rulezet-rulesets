rule TTP_XOR_MULT_DOSStub_64cb {
  strings:
    $key_64cb = { 30 a3 [2] 44 bb [2] 03 b9 [2] 44 a8 [2] 0a a4 [2] 06 ae [2] 11 a5 [2] 0a eb [2] 37 }

  condition:
    any of them
}