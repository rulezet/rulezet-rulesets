rule TTP_XOR_MULT_DOSStub_dcd4 {
  strings:
    $key_dcd4 = { 88 bc [2] fc a4 [2] bb a6 [2] fc b7 [2] b2 bb [2] be b1 [2] a9 ba [2] b2 f4 [2] 8f }

  condition:
    any of them
}