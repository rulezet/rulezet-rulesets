rule TTP_XOR_MULT_DOSStub_44cb {
  strings:
    $key_44cb = { 10 a3 [2] 64 bb [2] 23 b9 [2] 64 a8 [2] 2a a4 [2] 26 ae [2] 31 a5 [2] 2a eb [2] 17 }

  condition:
    any of them
}