rule TTP_XOR_MULT_DOSStub_81c5 {
  strings:
    $key_81c5 = { d5 ad [2] a1 b5 [2] e6 b7 [2] a1 a6 [2] ef aa [2] e3 a0 [2] f4 ab [2] ef e5 [2] d2 }

  condition:
    any of them
}