rule TTP_XOR_MULT_DOSStub_a4c2 {
  strings:
    $key_a4c2 = { f0 aa [2] 84 b2 [2] c3 b0 [2] 84 a1 [2] ca ad [2] c6 a7 [2] d1 ac [2] ca e2 [2] f7 }

  condition:
    any of them
}