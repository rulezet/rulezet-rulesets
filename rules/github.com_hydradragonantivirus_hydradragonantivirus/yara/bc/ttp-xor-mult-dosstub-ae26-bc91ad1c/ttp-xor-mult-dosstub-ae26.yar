rule TTP_XOR_MULT_DOSStub_ae26 {
  strings:
    $key_ae26 = { fa 4e [2] 8e 56 [2] c9 54 [2] 8e 45 [2] c0 49 [2] cc 43 [2] db 48 [2] c0 06 [2] fd }

  condition:
    any of them
}