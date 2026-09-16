rule TTP_XOR_MULT_DOSStub_16c5 {
  strings:
    $key_16c5 = { 42 ad [2] 36 b5 [2] 71 b7 [2] 36 a6 [2] 78 aa [2] 74 a0 [2] 63 ab [2] 78 e5 [2] 45 }

  condition:
    any of them
}