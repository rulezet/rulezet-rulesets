rule TTP_XOR_MULT_DOSStub_ae41 {
  strings:
    $key_ae41 = { fa 29 [2] 8e 31 [2] c9 33 [2] 8e 22 [2] c0 2e [2] cc 24 [2] db 2f [2] c0 61 [2] fd }

  condition:
    any of them
}