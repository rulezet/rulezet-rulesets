rule TTP_XOR_MULT_DOSStub_06c8 {
  strings:
    $key_06c8 = { 52 a0 [2] 26 b8 [2] 61 ba [2] 26 ab [2] 68 a7 [2] 64 ad [2] 73 a6 [2] 68 e8 [2] 55 }

  condition:
    any of them
}