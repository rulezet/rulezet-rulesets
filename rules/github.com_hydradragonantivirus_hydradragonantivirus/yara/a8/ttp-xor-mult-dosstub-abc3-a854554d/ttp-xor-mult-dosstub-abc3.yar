rule TTP_XOR_MULT_DOSStub_abc3 {
  strings:
    $key_abc3 = { ff ab [2] 8b b3 [2] cc b1 [2] 8b a0 [2] c5 ac [2] c9 a6 [2] de ad [2] c5 e3 [2] f8 }

  condition:
    any of them
}