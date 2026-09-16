rule TTP_XOR_MULT_DOSStub_aea6 {
  strings:
    $key_aea6 = { fa ce [2] 8e d6 [2] c9 d4 [2] 8e c5 [2] c0 c9 [2] cc c3 [2] db c8 [2] c0 86 [2] fd }

  condition:
    any of them
}