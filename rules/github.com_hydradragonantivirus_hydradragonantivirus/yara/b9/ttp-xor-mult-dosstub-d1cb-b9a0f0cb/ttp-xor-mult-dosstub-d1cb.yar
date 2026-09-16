rule TTP_XOR_MULT_DOSStub_d1cb {
  strings:
    $key_d1cb = { 85 a3 [2] f1 bb [2] b6 b9 [2] f1 a8 [2] bf a4 [2] b3 ae [2] a4 a5 [2] bf eb [2] 82 }

  condition:
    any of them
}