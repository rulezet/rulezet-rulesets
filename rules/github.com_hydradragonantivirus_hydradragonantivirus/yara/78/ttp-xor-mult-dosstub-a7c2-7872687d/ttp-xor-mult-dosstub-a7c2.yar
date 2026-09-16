rule TTP_XOR_MULT_DOSStub_a7c2 {
  strings:
    $key_a7c2 = { f3 aa [2] 87 b2 [2] c0 b0 [2] 87 a1 [2] c9 ad [2] c5 a7 [2] d2 ac [2] c9 e2 [2] f4 }

  condition:
    any of them
}