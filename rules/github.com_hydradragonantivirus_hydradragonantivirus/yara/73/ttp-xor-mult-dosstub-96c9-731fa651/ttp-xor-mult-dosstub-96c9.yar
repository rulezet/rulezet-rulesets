rule TTP_XOR_MULT_DOSStub_96c9 {
  strings:
    $key_96c9 = { c2 a1 [2] b6 b9 [2] f1 bb [2] b6 aa [2] f8 a6 [2] f4 ac [2] e3 a7 [2] f8 e9 [2] c5 }

  condition:
    any of them
}