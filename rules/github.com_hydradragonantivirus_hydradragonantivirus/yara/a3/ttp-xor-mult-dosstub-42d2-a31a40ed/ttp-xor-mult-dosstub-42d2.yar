rule TTP_XOR_MULT_DOSStub_42d2 {
  strings:
    $key_42d2 = { 16 ba [2] 62 a2 [2] 25 a0 [2] 62 b1 [2] 2c bd [2] 20 b7 [2] 37 bc [2] 2c f2 [2] 11 }

  condition:
    any of them
}