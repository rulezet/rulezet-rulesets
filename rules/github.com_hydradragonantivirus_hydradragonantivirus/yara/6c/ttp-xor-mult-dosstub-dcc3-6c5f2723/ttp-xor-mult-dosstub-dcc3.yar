rule TTP_XOR_MULT_DOSStub_dcc3 {
  strings:
    $key_dcc3 = { 88 ab [2] fc b3 [2] bb b1 [2] fc a0 [2] b2 ac [2] be a6 [2] a9 ad [2] b2 e3 [2] 8f }

  condition:
    any of them
}