rule TTP_XOR_MULT_DOSStub_d8cb {
  strings:
    $key_d8cb = { 8c a3 [2] f8 bb [2] bf b9 [2] f8 a8 [2] b6 a4 [2] ba ae [2] ad a5 [2] b6 eb [2] 8b }

  condition:
    any of them
}