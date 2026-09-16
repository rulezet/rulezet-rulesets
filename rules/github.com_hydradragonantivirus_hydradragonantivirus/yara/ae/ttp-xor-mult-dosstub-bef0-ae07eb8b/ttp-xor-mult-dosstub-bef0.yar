rule TTP_XOR_MULT_DOSStub_bef0 {
  strings:
    $key_bef0 = { ea 98 [2] 9e 80 [2] d9 82 [2] 9e 93 [2] d0 9f [2] dc 95 [2] cb 9e [2] d0 d0 [2] ed }

  condition:
    any of them
}