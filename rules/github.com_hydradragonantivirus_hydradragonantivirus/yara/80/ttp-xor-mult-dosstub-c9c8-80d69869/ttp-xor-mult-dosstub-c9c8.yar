rule TTP_XOR_MULT_DOSStub_c9c8 {
  strings:
    $key_c9c8 = { 9d a0 [2] e9 b8 [2] ae ba [2] e9 ab [2] a7 a7 [2] ab ad [2] bc a6 [2] a7 e8 [2] 9a }

  condition:
    any of them
}