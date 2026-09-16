rule TTP_XOR_MULT_DOSStub_ae47 {
  strings:
    $key_ae47 = { fa 2f [2] 8e 37 [2] c9 35 [2] 8e 24 [2] c0 28 [2] cc 22 [2] db 29 [2] c0 67 [2] fd }

  condition:
    any of them
}