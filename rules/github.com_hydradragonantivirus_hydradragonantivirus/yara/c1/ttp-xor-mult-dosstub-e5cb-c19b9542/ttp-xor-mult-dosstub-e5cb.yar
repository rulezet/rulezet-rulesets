rule TTP_XOR_MULT_DOSStub_e5cb {
  strings:
    $key_e5cb = { b1 a3 [2] c5 bb [2] 82 b9 [2] c5 a8 [2] 8b a4 [2] 87 ae [2] 90 a5 [2] 8b eb [2] b6 }

  condition:
    any of them
}