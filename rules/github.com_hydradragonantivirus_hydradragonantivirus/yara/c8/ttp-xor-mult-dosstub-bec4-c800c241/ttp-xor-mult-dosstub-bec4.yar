rule TTP_XOR_MULT_DOSStub_bec4 {
  strings:
    $key_bec4 = { ea ac [2] 9e b4 [2] d9 b6 [2] 9e a7 [2] d0 ab [2] dc a1 [2] cb aa [2] d0 e4 [2] ed }

  condition:
    any of them
}