rule TTP_XOR_MULT_DOSStub_aeb5 {
  strings:
    $key_aeb5 = { fa dd [2] 8e c5 [2] c9 c7 [2] 8e d6 [2] c0 da [2] cc d0 [2] db db [2] c0 95 [2] fd }

  condition:
    any of them
}