rule TTP_XOR_MULT_DOSStub_ae16 {
  strings:
    $key_ae16 = { fa 7e [2] 8e 66 [2] c9 64 [2] 8e 75 [2] c0 79 [2] cc 73 [2] db 78 [2] c0 36 [2] fd }

  condition:
    any of them
}