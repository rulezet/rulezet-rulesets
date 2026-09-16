rule TTP_XOR_MULT_DOSStub_bcc8 {
  strings:
    $key_bcc8 = { e8 a0 [2] 9c b8 [2] db ba [2] 9c ab [2] d2 a7 [2] de ad [2] c9 a6 [2] d2 e8 [2] ef }

  condition:
    any of them
}