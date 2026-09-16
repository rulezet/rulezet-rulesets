rule TTP_XOR_MULT_DOSStub_ae6d {
  strings:
    $key_ae6d = { fa 05 [2] 8e 1d [2] c9 1f [2] 8e 0e [2] c0 02 [2] cc 08 [2] db 03 [2] c0 4d [2] fd }

  condition:
    any of them
}