rule TTP_XOR_MULT_DOSStub_06c5 {
  strings:
    $key_06c5 = { 52 ad [2] 26 b5 [2] 61 b7 [2] 26 a6 [2] 68 aa [2] 64 a0 [2] 73 ab [2] 68 e5 [2] 55 }

  condition:
    any of them
}