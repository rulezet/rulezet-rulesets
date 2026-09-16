rule TTP_XOR_MULT_DOSStub_73c8 {
  strings:
    $key_73c8 = { 27 a0 [2] 53 b8 [2] 14 ba [2] 53 ab [2] 1d a7 [2] 11 ad [2] 06 a6 [2] 1d e8 [2] 20 }

  condition:
    any of them
}