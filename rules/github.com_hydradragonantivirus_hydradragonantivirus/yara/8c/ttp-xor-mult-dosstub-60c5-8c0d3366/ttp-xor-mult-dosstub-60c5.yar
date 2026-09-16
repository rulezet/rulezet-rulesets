rule TTP_XOR_MULT_DOSStub_60c5 {
  strings:
    $key_60c5 = { 34 ad [2] 40 b5 [2] 07 b7 [2] 40 a6 [2] 0e aa [2] 02 a0 [2] 15 ab [2] 0e e5 [2] 33 }

  condition:
    any of them
}