rule TTP_XOR_MULT_DOSStub_a98b {
  strings:
    $key_a98b = { fd e3 [2] 89 fb [2] ce f9 [2] 89 e8 [2] c7 e4 [2] cb ee [2] dc e5 [2] c7 ab [2] fa }

  condition:
    any of them
}