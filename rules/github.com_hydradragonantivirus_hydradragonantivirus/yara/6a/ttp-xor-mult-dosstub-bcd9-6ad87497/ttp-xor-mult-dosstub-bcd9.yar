rule TTP_XOR_MULT_DOSStub_bcd9 {
  strings:
    $key_bcd9 = { e8 b1 [2] 9c a9 [2] db ab [2] 9c ba [2] d2 b6 [2] de bc [2] c9 b7 [2] d2 f9 [2] ef }

  condition:
    any of them
}