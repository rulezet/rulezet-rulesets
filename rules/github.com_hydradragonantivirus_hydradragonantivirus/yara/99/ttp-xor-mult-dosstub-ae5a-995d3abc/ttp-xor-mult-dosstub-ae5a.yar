rule TTP_XOR_MULT_DOSStub_ae5a {
  strings:
    $key_ae5a = { fa 32 [2] 8e 2a [2] c9 28 [2] 8e 39 [2] c0 35 [2] cc 3f [2] db 34 [2] c0 7a [2] fd }

  condition:
    any of them
}