rule TTP_XOR_MULT_DOSStub_90cb {
  strings:
    $key_90cb = { c4 a3 [2] b0 bb [2] f7 b9 [2] b0 a8 [2] fe a4 [2] f2 ae [2] e5 a5 [2] fe eb [2] c3 }

  condition:
    any of them
}