rule TTP_XOR_MULT_DOSStub_32d6 {
  strings:
    $key_32d6 = { 66 be [2] 12 a6 [2] 55 a4 [2] 12 b5 [2] 5c b9 [2] 50 b3 [2] 47 b8 [2] 5c f6 [2] 61 }

  condition:
    any of them
}