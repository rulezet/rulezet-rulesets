rule TTP_XOR_MULT_DOSStub_bea9 {
  strings:
    $key_bea9 = { ea c1 [2] 9e d9 [2] d9 db [2] 9e ca [2] d0 c6 [2] dc cc [2] cb c7 [2] d0 89 [2] ed }

  condition:
    any of them
}