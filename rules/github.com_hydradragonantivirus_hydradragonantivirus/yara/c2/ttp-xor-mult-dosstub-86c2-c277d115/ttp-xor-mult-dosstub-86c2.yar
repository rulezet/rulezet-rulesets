rule TTP_XOR_MULT_DOSStub_86c2 {
  strings:
    $key_86c2 = { d2 aa [2] a6 b2 [2] e1 b0 [2] a6 a1 [2] e8 ad [2] e4 a7 [2] f3 ac [2] e8 e2 [2] d5 }

  condition:
    any of them
}