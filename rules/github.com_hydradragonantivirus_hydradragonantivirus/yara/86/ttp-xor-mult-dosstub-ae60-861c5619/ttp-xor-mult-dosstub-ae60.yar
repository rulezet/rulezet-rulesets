rule TTP_XOR_MULT_DOSStub_ae60 {
  strings:
    $key_ae60 = { fa 08 [2] 8e 10 [2] c9 12 [2] 8e 03 [2] c0 0f [2] cc 05 [2] db 0e [2] c0 40 [2] fd }

  condition:
    any of them
}