rule TTP_XOR_MULT_DOSStub_ae54 {
  strings:
    $key_ae54 = { fa 3c [2] 8e 24 [2] c9 26 [2] 8e 37 [2] c0 3b [2] cc 31 [2] db 3a [2] c0 74 [2] fd }

  condition:
    any of them
}