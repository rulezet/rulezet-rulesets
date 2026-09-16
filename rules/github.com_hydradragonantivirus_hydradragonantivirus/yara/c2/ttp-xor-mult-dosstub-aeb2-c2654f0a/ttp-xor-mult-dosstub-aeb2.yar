rule TTP_XOR_MULT_DOSStub_aeb2 {
  strings:
    $key_aeb2 = { fa da [2] 8e c2 [2] c9 c0 [2] 8e d1 [2] c0 dd [2] cc d7 [2] db dc [2] c0 92 [2] fd }

  condition:
    any of them
}