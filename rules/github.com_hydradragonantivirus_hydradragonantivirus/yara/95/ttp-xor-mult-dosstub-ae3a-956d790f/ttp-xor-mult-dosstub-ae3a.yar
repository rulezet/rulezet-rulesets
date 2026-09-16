rule TTP_XOR_MULT_DOSStub_ae3a {
  strings:
    $key_ae3a = { fa 52 [2] 8e 4a [2] c9 48 [2] 8e 59 [2] c0 55 [2] cc 5f [2] db 54 [2] c0 1a [2] fd }

  condition:
    any of them
}