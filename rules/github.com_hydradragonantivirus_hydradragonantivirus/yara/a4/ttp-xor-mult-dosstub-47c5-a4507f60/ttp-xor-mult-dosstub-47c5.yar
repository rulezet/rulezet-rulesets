rule TTP_XOR_MULT_DOSStub_47c5 {
  strings:
    $key_47c5 = { 13 ad [2] 67 b5 [2] 20 b7 [2] 67 a6 [2] 29 aa [2] 25 a0 [2] 32 ab [2] 29 e5 [2] 14 }

  condition:
    any of them
}