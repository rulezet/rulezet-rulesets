rule TTP_XOR_MULT_DOSStub_6c98 {
  strings:
    $key_6c98 = { 38 f0 [2] 4c e8 [2] 0b ea [2] 4c fb [2] 02 f7 [2] 0e fd [2] 19 f6 [2] 02 b8 [2] 3f }

  condition:
    any of them
}