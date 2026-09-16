rule TTP_XOR_MULT_DOSStub_dcd3 {
  strings:
    $key_dcd3 = { 88 bb [2] fc a3 [2] bb a1 [2] fc b0 [2] b2 bc [2] be b6 [2] a9 bd [2] b2 f3 [2] 8f }

  condition:
    any of them
}