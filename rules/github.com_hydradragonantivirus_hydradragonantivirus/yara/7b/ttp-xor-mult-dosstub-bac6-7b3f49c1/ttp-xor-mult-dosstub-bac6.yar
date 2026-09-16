rule TTP_XOR_MULT_DOSStub_bac6 {
  strings:
    $key_bac6 = { ee ae [2] 9a b6 [2] dd b4 [2] 9a a5 [2] d4 a9 [2] d8 a3 [2] cf a8 [2] d4 e6 [2] e9 }

  condition:
    any of them
}