rule TTP_XOR_MULT_DOSStub_f5cb {
  strings:
    $key_f5cb = { a1 a3 [2] d5 bb [2] 92 b9 [2] d5 a8 [2] 9b a4 [2] 97 ae [2] 80 a5 [2] 9b eb [2] a6 }

  condition:
    any of them
}