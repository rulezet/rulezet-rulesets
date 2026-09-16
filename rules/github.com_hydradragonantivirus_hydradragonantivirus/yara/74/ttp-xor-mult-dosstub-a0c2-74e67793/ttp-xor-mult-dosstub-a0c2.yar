rule TTP_XOR_MULT_DOSStub_a0c2 {
  strings:
    $key_a0c2 = { f4 aa [2] 80 b2 [2] c7 b0 [2] 80 a1 [2] ce ad [2] c2 a7 [2] d5 ac [2] ce e2 [2] f3 }

  condition:
    any of them
}