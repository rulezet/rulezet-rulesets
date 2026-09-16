rule TTP_XOR_MULT_DOSStub_ae4a {
  strings:
    $key_ae4a = { fa 22 [2] 8e 3a [2] c9 38 [2] 8e 29 [2] c0 25 [2] cc 2f [2] db 24 [2] c0 6a [2] fd }

  condition:
    any of them
}