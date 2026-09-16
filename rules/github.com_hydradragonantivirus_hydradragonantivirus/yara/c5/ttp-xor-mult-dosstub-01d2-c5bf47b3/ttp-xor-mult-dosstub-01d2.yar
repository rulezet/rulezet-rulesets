rule TTP_XOR_MULT_DOSStub_01d2 {
  strings:
    $key_01d2 = { 55 ba [2] 21 a2 [2] 66 a0 [2] 21 b1 [2] 6f bd [2] 63 b7 [2] 74 bc [2] 6f f2 [2] 52 }

  condition:
    any of them
}