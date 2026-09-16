rule TTP_XOR_MULT_DOSStub_bef7 {
  strings:
    $key_bef7 = { ea 9f [2] 9e 87 [2] d9 85 [2] 9e 94 [2] d0 98 [2] dc 92 [2] cb 99 [2] d0 d7 [2] ed }

  condition:
    any of them
}