rule TTP_XOR_MULT_DOSStub_ae13 {
  strings:
    $key_ae13 = { fa 7b [2] 8e 63 [2] c9 61 [2] 8e 70 [2] c0 7c [2] cc 76 [2] db 7d [2] c0 33 [2] fd }

  condition:
    any of them
}