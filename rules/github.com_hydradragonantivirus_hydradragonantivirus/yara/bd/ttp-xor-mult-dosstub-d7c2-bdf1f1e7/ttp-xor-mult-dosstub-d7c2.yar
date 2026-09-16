rule TTP_XOR_MULT_DOSStub_d7c2 {
  strings:
    $key_d7c2 = { 83 aa [2] f7 b2 [2] b0 b0 [2] f7 a1 [2] b9 ad [2] b5 a7 [2] a2 ac [2] b9 e2 [2] 84 }

  condition:
    any of them
}