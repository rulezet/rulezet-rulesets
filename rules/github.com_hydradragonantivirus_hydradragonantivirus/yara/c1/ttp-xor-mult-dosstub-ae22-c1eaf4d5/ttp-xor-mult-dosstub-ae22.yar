rule TTP_XOR_MULT_DOSStub_ae22 {
  strings:
    $key_ae22 = { fa 4a [2] 8e 52 [2] c9 50 [2] 8e 41 [2] c0 4d [2] cc 47 [2] db 4c [2] c0 02 [2] fd }

  condition:
    any of them
}