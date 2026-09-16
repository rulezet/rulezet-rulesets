rule TTP_XOR_MULT_DOSStub_bec9 {
  strings:
    $key_bec9 = { ea a1 [2] 9e b9 [2] d9 bb [2] 9e aa [2] d0 a6 [2] dc ac [2] cb a7 [2] d0 e9 [2] ed }

  condition:
    any of them
}