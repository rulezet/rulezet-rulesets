rule TTP_XOR_MULT_DOSStub_92cb {
  strings:
    $key_92cb = { c6 a3 [2] b2 bb [2] f5 b9 [2] b2 a8 [2] fc a4 [2] f0 ae [2] e7 a5 [2] fc eb [2] c1 }

  condition:
    any of them
}