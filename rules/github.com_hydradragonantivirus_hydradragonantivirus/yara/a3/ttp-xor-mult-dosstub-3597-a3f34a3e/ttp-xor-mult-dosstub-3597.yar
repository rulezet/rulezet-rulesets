rule TTP_XOR_MULT_DOSStub_3597 {
  strings:
    $key_3597 = { 61 ff [2] 15 e7 [2] 52 e5 [2] 15 f4 [2] 5b f8 [2] 57 f2 [2] 40 f9 [2] 5b b7 [2] 66 }

  condition:
    any of them
}