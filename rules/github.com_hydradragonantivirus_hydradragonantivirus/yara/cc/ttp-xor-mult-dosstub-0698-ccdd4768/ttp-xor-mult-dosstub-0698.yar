rule TTP_XOR_MULT_DOSStub_0698 {
  strings:
    $key_0698 = { 52 f0 [2] 26 e8 [2] 61 ea [2] 26 fb [2] 68 f7 [2] 64 fd [2] 73 f6 [2] 68 b8 [2] 55 }

  condition:
    any of them
}