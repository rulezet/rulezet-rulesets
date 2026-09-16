rule TTP_XOR_MULT_DOSStub_ae7d {
  strings:
    $key_ae7d = { fa 15 [2] 8e 0d [2] c9 0f [2] 8e 1e [2] c0 12 [2] cc 18 [2] db 13 [2] c0 5d [2] fd }

  condition:
    any of them
}