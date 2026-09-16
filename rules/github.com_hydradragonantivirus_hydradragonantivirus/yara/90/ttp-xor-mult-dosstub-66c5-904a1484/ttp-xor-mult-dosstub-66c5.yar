rule TTP_XOR_MULT_DOSStub_66c5 {
  strings:
    $key_66c5 = { 32 ad [2] 46 b5 [2] 01 b7 [2] 46 a6 [2] 08 aa [2] 04 a0 [2] 13 ab [2] 08 e5 [2] 35 }

  condition:
    any of them
}