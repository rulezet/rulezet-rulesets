rule TTP_XOR_MULT_DOSStub_ae71 {
  strings:
    $key_ae71 = { fa 19 [2] 8e 01 [2] c9 03 [2] 8e 12 [2] c0 1e [2] cc 14 [2] db 1f [2] c0 51 [2] fd }

  condition:
    any of them
}