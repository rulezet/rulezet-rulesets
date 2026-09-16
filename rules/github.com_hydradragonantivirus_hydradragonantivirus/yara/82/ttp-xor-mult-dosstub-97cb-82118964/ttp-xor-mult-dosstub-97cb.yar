rule TTP_XOR_MULT_DOSStub_97cb {
  strings:
    $key_97cb = { c3 a3 [2] b7 bb [2] f0 b9 [2] b7 a8 [2] f9 a4 [2] f5 ae [2] e2 a5 [2] f9 eb [2] c4 }

  condition:
    any of them
}