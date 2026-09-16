rule TTP_XOR_MULT_DOSStub_ae34 {
  strings:
    $key_ae34 = { fa 5c [2] 8e 44 [2] c9 46 [2] 8e 57 [2] c0 5b [2] cc 51 [2] db 5a [2] c0 14 [2] fd }

  condition:
    any of them
}