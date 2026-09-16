rule TTP_XOR_MULT_DOSStub_ae39 {
  strings:
    $key_ae39 = { fa 51 [2] 8e 49 [2] c9 4b [2] 8e 5a [2] c0 56 [2] cc 5c [2] db 57 [2] c0 19 [2] fd }

  condition:
    any of them
}