rule TTP_XOR_MULT_DOSStub_84c2 {
  strings:
    $key_84c2 = { d0 aa [2] a4 b2 [2] e3 b0 [2] a4 a1 [2] ea ad [2] e6 a7 [2] f1 ac [2] ea e2 [2] d7 }

  condition:
    any of them
}