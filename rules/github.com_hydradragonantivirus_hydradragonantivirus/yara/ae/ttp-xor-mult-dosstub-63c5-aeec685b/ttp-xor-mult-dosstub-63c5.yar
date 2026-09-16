rule TTP_XOR_MULT_DOSStub_63c5 {
  strings:
    $key_63c5 = { 37 ad [2] 43 b5 [2] 04 b7 [2] 43 a6 [2] 0d aa [2] 01 a0 [2] 16 ab [2] 0d e5 [2] 30 }

  condition:
    any of them
}