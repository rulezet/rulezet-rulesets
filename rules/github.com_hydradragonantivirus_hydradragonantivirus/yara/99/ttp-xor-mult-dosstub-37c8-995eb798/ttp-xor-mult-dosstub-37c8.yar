rule TTP_XOR_MULT_DOSStub_37c8 {
  strings:
    $key_37c8 = { 63 a0 [2] 17 b8 [2] 50 ba [2] 17 ab [2] 59 a7 [2] 55 ad [2] 42 a6 [2] 59 e8 [2] 64 }

  condition:
    any of them
}