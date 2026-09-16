rule TTP_XOR_MULT_DOSStub_bea2 {
  strings:
    $key_bea2 = { ea ca [2] 9e d2 [2] d9 d0 [2] 9e c1 [2] d0 cd [2] dc c7 [2] cb cc [2] d0 82 [2] ed }

  condition:
    any of them
}