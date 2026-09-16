rule TTP_XOR_MULT_DOSStub_beb1 {
  strings:
    $key_beb1 = { ea d9 [2] 9e c1 [2] d9 c3 [2] 9e d2 [2] d0 de [2] dc d4 [2] cb df [2] d0 91 [2] ed }

  condition:
    any of them
}