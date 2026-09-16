rule TTP_XOR_MULT_DOSStub_ae0a {
  strings:
    $key_ae0a = { fa 62 [2] 8e 7a [2] c9 78 [2] 8e 69 [2] c0 65 [2] cc 6f [2] db 64 [2] c0 2a [2] fd }

  condition:
    any of them
}