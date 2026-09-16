rule TTP_XOR_MULT_DOSStub_bef6 {
  strings:
    $key_bef6 = { ea 9e [2] 9e 86 [2] d9 84 [2] 9e 95 [2] d0 99 [2] dc 93 [2] cb 98 [2] d0 d6 [2] ed }

  condition:
    any of them
}