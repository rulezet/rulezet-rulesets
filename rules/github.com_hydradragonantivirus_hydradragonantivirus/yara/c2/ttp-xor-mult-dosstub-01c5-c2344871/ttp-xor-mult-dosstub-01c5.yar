rule TTP_XOR_MULT_DOSStub_01c5 {
  strings:
    $key_01c5 = { 55 ad [2] 21 b5 [2] 66 b7 [2] 21 a6 [2] 6f aa [2] 63 a0 [2] 74 ab [2] 6f e5 [2] 52 }

  condition:
    any of them
}