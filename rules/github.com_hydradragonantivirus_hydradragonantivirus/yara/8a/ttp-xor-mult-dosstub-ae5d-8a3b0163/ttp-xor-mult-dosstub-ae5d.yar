rule TTP_XOR_MULT_DOSStub_ae5d {
  strings:
    $key_ae5d = { fa 35 [2] 8e 2d [2] c9 2f [2] 8e 3e [2] c0 32 [2] cc 38 [2] db 33 [2] c0 7d [2] fd }

  condition:
    any of them
}