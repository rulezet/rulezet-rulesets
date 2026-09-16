rule TTP_XOR_MULT_DOSStub_bef1 {
  strings:
    $key_bef1 = { ea 99 [2] 9e 81 [2] d9 83 [2] 9e 92 [2] d0 9e [2] dc 94 [2] cb 9f [2] d0 d1 [2] ed }

  condition:
    any of them
}