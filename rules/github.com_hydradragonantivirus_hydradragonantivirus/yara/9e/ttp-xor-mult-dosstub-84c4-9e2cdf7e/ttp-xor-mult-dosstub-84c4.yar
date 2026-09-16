rule TTP_XOR_MULT_DOSStub_84c4 {
  strings:
    $key_84c4 = { d0 ac [2] a4 b4 [2] e3 b6 [2] a4 a7 [2] ea ab [2] e6 a1 [2] f1 aa [2] ea e4 [2] d7 }

  condition:
    any of them
}