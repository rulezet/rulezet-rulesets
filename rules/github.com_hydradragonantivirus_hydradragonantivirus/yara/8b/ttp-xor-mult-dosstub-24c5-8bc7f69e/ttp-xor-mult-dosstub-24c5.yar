rule TTP_XOR_MULT_DOSStub_24c5 {
  strings:
    $key_24c5 = { 70 ad [2] 04 b5 [2] 43 b7 [2] 04 a6 [2] 4a aa [2] 46 a0 [2] 51 ab [2] 4a e5 [2] 77 }

  condition:
    any of them
}