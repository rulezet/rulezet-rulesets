rule TTP_XOR_MULT_DOSStub_aefa {
  strings:
    $key_aefa = { fa 92 [2] 8e 8a [2] c9 88 [2] 8e 99 [2] c0 95 [2] cc 9f [2] db 94 [2] c0 da [2] fd }

  condition:
    any of them
}