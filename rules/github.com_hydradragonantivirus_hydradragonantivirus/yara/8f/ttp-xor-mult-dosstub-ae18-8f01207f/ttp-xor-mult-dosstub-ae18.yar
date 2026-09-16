rule TTP_XOR_MULT_DOSStub_ae18 {
  strings:
    $key_ae18 = { fa 70 [2] 8e 68 [2] c9 6a [2] 8e 7b [2] c0 77 [2] cc 7d [2] db 76 [2] c0 38 [2] fd }

  condition:
    any of them
}