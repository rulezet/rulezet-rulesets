rule TTP_XOR_MULT_DOSStub_ae43 {
  strings:
    $key_ae43 = { fa 2b [2] 8e 33 [2] c9 31 [2] 8e 20 [2] c0 2c [2] cc 26 [2] db 2d [2] c0 63 [2] fd }

  condition:
    any of them
}