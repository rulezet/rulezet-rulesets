rule TTP_XOR_MULT_DOSStub_52d6 {
  strings:
    $key_52d6 = { 06 be [2] 72 a6 [2] 35 a4 [2] 72 b5 [2] 3c b9 [2] 30 b3 [2] 27 b8 [2] 3c f6 [2] 01 }

  condition:
    any of them
}