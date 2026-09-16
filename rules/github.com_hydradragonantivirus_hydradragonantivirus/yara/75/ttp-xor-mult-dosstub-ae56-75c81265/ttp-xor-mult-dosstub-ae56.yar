rule TTP_XOR_MULT_DOSStub_ae56 {
  strings:
    $key_ae56 = { fa 3e [2] 8e 26 [2] c9 24 [2] 8e 35 [2] c0 39 [2] cc 33 [2] db 38 [2] c0 76 [2] fd }

  condition:
    any of them
}