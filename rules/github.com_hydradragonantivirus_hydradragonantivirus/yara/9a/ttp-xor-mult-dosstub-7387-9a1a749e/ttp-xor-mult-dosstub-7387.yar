rule TTP_XOR_MULT_DOSStub_7387 {
  strings:
    $key_7387 = { 27 ef [2] 53 f7 [2] 14 f5 [2] 53 e4 [2] 1d e8 [2] 11 e2 [2] 06 e9 [2] 1d a7 [2] 20 }

  condition:
    any of them
}