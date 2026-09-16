rule TTP_XOR_MULT_DOSStub_d99d {
  strings:
    $key_d99d = { 8d f5 [2] f9 ed [2] be ef [2] f9 fe [2] b7 f2 [2] bb f8 [2] ac f3 [2] b7 bd [2] 8a }

  condition:
    any of them
}