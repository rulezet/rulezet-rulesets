rule TTP_XOR_MULT_DOSStub_ae04 {
  strings:
    $key_ae04 = { fa 6c [2] 8e 74 [2] c9 76 [2] 8e 67 [2] c0 6b [2] cc 61 [2] db 6a [2] c0 24 [2] fd }

  condition:
    any of them
}