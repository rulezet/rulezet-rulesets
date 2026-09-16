rule TTP_XOR_MULT_DOSStub_dcc9 {
  strings:
    $key_dcc9 = { 88 a1 [2] fc b9 [2] bb bb [2] fc aa [2] b2 a6 [2] be ac [2] a9 a7 [2] b2 e9 [2] 8f }

  condition:
    any of them
}