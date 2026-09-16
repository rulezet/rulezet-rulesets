rule TTP_XOR_MULT_DOSStub_bcd3 {
  strings:
    $key_bcd3 = { e8 bb [2] 9c a3 [2] db a1 [2] 9c b0 [2] d2 bc [2] de b6 [2] c9 bd [2] d2 f3 [2] ef }

  condition:
    any of them
}