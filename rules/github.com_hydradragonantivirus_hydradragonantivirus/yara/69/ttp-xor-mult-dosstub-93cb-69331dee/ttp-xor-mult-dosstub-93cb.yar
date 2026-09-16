rule TTP_XOR_MULT_DOSStub_93cb {
  strings:
    $key_93cb = { c7 a3 [2] b3 bb [2] f4 b9 [2] b3 a8 [2] fd a4 [2] f1 ae [2] e6 a5 [2] fd eb [2] c0 }

  condition:
    any of them
}