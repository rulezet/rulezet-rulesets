rule TTP_XOR_MULT_DOSStub_bcd7 {
  strings:
    $key_bcd7 = { e8 bf [2] 9c a7 [2] db a5 [2] 9c b4 [2] d2 b8 [2] de b2 [2] c9 b9 [2] d2 f7 [2] ef }

  condition:
    any of them
}