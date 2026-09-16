rule TTP_XOR_MULT_DOSStub_d998 {
  strings:
    $key_d998 = { 8d f0 [2] f9 e8 [2] be ea [2] f9 fb [2] b7 f7 [2] bb fd [2] ac f6 [2] b7 b8 [2] 8a }

  condition:
    any of them
}