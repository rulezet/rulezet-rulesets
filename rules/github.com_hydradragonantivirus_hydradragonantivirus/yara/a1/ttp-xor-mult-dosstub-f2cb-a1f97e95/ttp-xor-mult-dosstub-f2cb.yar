rule TTP_XOR_MULT_DOSStub_f2cb {
  strings:
    $key_f2cb = { a6 a3 [2] d2 bb [2] 95 b9 [2] d2 a8 [2] 9c a4 [2] 90 ae [2] 87 a5 [2] 9c eb [2] a1 }

  condition:
    any of them
}