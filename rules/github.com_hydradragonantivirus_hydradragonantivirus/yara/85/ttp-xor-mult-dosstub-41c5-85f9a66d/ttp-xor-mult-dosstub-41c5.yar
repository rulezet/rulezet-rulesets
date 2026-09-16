rule TTP_XOR_MULT_DOSStub_41c5 {
  strings:
    $key_41c5 = { 15 ad [2] 61 b5 [2] 26 b7 [2] 61 a6 [2] 2f aa [2] 23 a0 [2] 34 ab [2] 2f e5 [2] 12 }

  condition:
    any of them
}