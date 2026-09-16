rule TTP_XOR_MULT_DOSStub_ae1a {
  strings:
    $key_ae1a = { fa 72 [2] 8e 6a [2] c9 68 [2] 8e 79 [2] c0 75 [2] cc 7f [2] db 74 [2] c0 3a [2] fd }

  condition:
    any of them
}