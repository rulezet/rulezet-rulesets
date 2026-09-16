rule TTP_XOR_MULT_DOSStub_ae32 {
  strings:
    $key_ae32 = { fa 5a [2] 8e 42 [2] c9 40 [2] 8e 51 [2] c0 5d [2] cc 57 [2] db 5c [2] c0 12 [2] fd }

  condition:
    any of them
}