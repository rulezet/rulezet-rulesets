rule TTP_XOR_MULT_DOSStub_ae4c {
  strings:
    $key_ae4c = { fa 24 [2] 8e 3c [2] c9 3e [2] 8e 2f [2] c0 23 [2] cc 29 [2] db 22 [2] c0 6c [2] fd }

  condition:
    any of them
}