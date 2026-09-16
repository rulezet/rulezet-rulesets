rule TTP_XOR_MULT_DOSStub_ae30 {
  strings:
    $key_ae30 = { fa 58 [2] 8e 40 [2] c9 42 [2] 8e 53 [2] c0 5f [2] cc 55 [2] db 5e [2] c0 10 [2] fd }

  condition:
    any of them
}