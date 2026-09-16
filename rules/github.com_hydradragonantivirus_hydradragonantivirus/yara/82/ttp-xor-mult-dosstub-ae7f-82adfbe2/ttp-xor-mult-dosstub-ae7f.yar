rule TTP_XOR_MULT_DOSStub_ae7f {
  strings:
    $key_ae7f = { fa 17 [2] 8e 0f [2] c9 0d [2] 8e 1c [2] c0 10 [2] cc 1a [2] db 11 [2] c0 5f [2] fd }

  condition:
    any of them
}