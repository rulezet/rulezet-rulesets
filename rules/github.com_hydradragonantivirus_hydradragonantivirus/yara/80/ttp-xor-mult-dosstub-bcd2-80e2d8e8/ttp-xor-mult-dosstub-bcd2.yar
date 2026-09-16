rule TTP_XOR_MULT_DOSStub_bcd2 {
  strings:
    $key_bcd2 = { e8 ba [2] 9c a2 [2] db a0 [2] 9c b1 [2] d2 bd [2] de b7 [2] c9 bc [2] d2 f2 [2] ef }

  condition:
    any of them
}