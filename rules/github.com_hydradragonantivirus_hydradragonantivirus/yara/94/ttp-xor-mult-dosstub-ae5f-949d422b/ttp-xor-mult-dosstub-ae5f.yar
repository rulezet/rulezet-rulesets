rule TTP_XOR_MULT_DOSStub_ae5f {
  strings:
    $key_ae5f = { fa 37 [2] 8e 2f [2] c9 2d [2] 8e 3c [2] c0 30 [2] cc 3a [2] db 31 [2] c0 7f [2] fd }

  condition:
    any of them
}