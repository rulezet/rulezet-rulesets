rule TTP_XOR_MULT_DOSStub_dcc8 {
  strings:
    $key_dcc8 = { 88 a0 [2] fc b8 [2] bb ba [2] fc ab [2] b2 a7 [2] be ad [2] a9 a6 [2] b2 e8 [2] 8f }

  condition:
    any of them
}