rule TTP_XOR_MULT_DOSStub_a1c2 {
  strings:
    $key_a1c2 = { f5 aa [2] 81 b2 [2] c6 b0 [2] 81 a1 [2] cf ad [2] c3 a7 [2] d4 ac [2] cf e2 [2] f2 }

  condition:
    any of them
}