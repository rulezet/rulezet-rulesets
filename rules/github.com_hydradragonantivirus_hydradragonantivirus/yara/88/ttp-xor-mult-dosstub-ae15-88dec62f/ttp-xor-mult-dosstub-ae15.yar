rule TTP_XOR_MULT_DOSStub_ae15 {
  strings:
    $key_ae15 = { fa 7d [2] 8e 65 [2] c9 67 [2] 8e 76 [2] c0 7a [2] cc 70 [2] db 7b [2] c0 35 [2] fd }

  condition:
    any of them
}