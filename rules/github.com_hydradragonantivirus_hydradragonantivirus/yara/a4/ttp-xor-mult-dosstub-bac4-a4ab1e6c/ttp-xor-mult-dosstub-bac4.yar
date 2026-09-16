rule TTP_XOR_MULT_DOSStub_bac4 {
  strings:
    $key_bac4 = { ee ac [2] 9a b4 [2] dd b6 [2] 9a a7 [2] d4 ab [2] d8 a1 [2] cf aa [2] d4 e4 [2] e9 }

  condition:
    any of them
}