rule TTP_XOR_MULT_DOSStub_7297 {
  strings:
    $key_7297 = { 26 ff [2] 52 e7 [2] 15 e5 [2] 52 f4 [2] 1c f8 [2] 10 f2 [2] 07 f9 [2] 1c b7 [2] 21 }

  condition:
    any of them
}