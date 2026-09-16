rule TTP_XOR_MULT_DOSStub_dcd5 {
  strings:
    $key_dcd5 = { 88 bd [2] fc a5 [2] bb a7 [2] fc b6 [2] b2 ba [2] be b0 [2] a9 bb [2] b2 f5 [2] 8f }

  condition:
    any of them
}