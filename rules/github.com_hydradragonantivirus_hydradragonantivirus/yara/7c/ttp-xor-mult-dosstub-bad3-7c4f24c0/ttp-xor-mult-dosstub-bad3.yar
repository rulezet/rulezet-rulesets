rule TTP_XOR_MULT_DOSStub_bad3 {
  strings:
    $key_bad3 = { ee bb [2] 9a a3 [2] dd a1 [2] 9a b0 [2] d4 bc [2] d8 b6 [2] cf bd [2] d4 f3 [2] e9 }

  condition:
    any of them
}