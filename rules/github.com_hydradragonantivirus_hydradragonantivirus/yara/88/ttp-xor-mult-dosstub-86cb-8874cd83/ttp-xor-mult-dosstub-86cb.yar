rule TTP_XOR_MULT_DOSStub_86cb {
  strings:
    $key_86cb = { d2 a3 [2] a6 bb [2] e1 b9 [2] a6 a8 [2] e8 a4 [2] e4 ae [2] f3 a5 [2] e8 eb [2] d5 }

  condition:
    any of them
}