rule TTP_XOR_MULT_DOSStub_77c5 {
  strings:
    $key_77c5 = { 23 ad [2] 57 b5 [2] 10 b7 [2] 57 a6 [2] 19 aa [2] 15 a0 [2] 02 ab [2] 19 e5 [2] 24 }

  condition:
    any of them
}