rule TTP_XOR_MULT_DOSStub_17c5 {
  strings:
    $key_17c5 = { 43 ad [2] 37 b5 [2] 70 b7 [2] 37 a6 [2] 79 aa [2] 75 a0 [2] 62 ab [2] 79 e5 [2] 44 }

  condition:
    any of them
}