rule TTP_XOR_MULT_DOSStub_ae21 {
  strings:
    $key_ae21 = { fa 49 [2] 8e 51 [2] c9 53 [2] 8e 42 [2] c0 4e [2] cc 44 [2] db 4f [2] c0 01 [2] fd }

  condition:
    any of them
}