rule TTP_XOR_MULT_DOSStub_c8c3 {
  strings:
    $key_c8c3 = { 9c ab [2] e8 b3 [2] af b1 [2] e8 a0 [2] a6 ac [2] aa a6 [2] bd ad [2] a6 e3 [2] 9b }

  condition:
    any of them
}