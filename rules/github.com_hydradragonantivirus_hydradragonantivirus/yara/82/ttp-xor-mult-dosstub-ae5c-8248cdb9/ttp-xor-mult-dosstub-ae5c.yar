rule TTP_XOR_MULT_DOSStub_ae5c {
  strings:
    $key_ae5c = { fa 34 [2] 8e 2c [2] c9 2e [2] 8e 3f [2] c0 33 [2] cc 39 [2] db 32 [2] c0 7c [2] fd }

  condition:
    any of them
}