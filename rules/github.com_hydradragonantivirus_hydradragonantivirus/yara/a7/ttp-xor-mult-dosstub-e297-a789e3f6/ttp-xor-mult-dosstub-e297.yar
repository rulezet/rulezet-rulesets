rule TTP_XOR_MULT_DOSStub_e297 {
  strings:
    $key_e297 = { b6 ff [2] c2 e7 [2] 85 e5 [2] c2 f4 [2] 8c f8 [2] 80 f2 [2] 97 f9 [2] 8c b7 [2] b1 }

  condition:
    any of them
}