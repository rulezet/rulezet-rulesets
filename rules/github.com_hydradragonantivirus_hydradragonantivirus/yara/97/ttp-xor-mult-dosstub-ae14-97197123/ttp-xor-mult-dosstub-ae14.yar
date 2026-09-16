rule TTP_XOR_MULT_DOSStub_ae14 {
  strings:
    $key_ae14 = { fa 7c [2] 8e 64 [2] c9 66 [2] 8e 77 [2] c0 7b [2] cc 71 [2] db 7a [2] c0 34 [2] fd }

  condition:
    any of them
}