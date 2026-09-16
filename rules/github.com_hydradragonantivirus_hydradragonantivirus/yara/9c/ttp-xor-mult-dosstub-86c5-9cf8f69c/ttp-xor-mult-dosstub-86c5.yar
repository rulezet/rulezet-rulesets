rule TTP_XOR_MULT_DOSStub_86c5 {
  strings:
    $key_86c5 = { d2 ad [2] a6 b5 [2] e1 b7 [2] a6 a6 [2] e8 aa [2] e4 a0 [2] f3 ab [2] e8 e5 [2] d5 }

  condition:
    any of them
}