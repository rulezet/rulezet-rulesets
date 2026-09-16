rule TTP_XOR_MULT_DOSStub_bac7 {
  strings:
    $key_bac7 = { ee af [2] 9a b7 [2] dd b5 [2] 9a a4 [2] d4 a8 [2] d8 a2 [2] cf a9 [2] d4 e7 [2] e9 }

  condition:
    any of them
}