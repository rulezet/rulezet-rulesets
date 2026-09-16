rule TTP_XOR_MULT_DOSStub_84c5 {
  strings:
    $key_84c5 = { d0 ad [2] a4 b5 [2] e3 b7 [2] a4 a6 [2] ea aa [2] e6 a0 [2] f1 ab [2] ea e5 [2] d7 }

  condition:
    any of them
}