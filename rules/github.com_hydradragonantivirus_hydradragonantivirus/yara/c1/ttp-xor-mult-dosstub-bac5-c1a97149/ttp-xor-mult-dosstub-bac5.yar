rule TTP_XOR_MULT_DOSStub_bac5 {
  strings:
    $key_bac5 = { ee ad [2] 9a b5 [2] dd b7 [2] 9a a6 [2] d4 aa [2] d8 a0 [2] cf ab [2] d4 e5 [2] e9 }

  condition:
    any of them
}