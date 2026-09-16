rule TTP_XOR_MULT_DOSStub_76c5 {
  strings:
    $key_76c5 = { 22 ad [2] 56 b5 [2] 11 b7 [2] 56 a6 [2] 18 aa [2] 14 a0 [2] 03 ab [2] 18 e5 [2] 25 }

  condition:
    any of them
}