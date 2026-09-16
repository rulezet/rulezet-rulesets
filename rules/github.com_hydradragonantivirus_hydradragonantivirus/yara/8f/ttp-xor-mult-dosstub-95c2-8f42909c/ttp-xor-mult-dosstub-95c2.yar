rule TTP_XOR_MULT_DOSStub_95c2 {
  strings:
    $key_95c2 = { c1 aa [2] b5 b2 [2] f2 b0 [2] b5 a1 [2] fb ad [2] f7 a7 [2] e0 ac [2] fb e2 [2] c6 }

  condition:
    any of them
}