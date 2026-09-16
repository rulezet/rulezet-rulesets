rule TTP_XOR_MULT_DOSStub_d9c3 {
  strings:
    $key_d9c3 = { 8d ab [2] f9 b3 [2] be b1 [2] f9 a0 [2] b7 ac [2] bb a6 [2] ac ad [2] b7 e3 [2] 8a }

  condition:
    any of them
}