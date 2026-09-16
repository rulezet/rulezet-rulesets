rule TTP_XOR_MULT_DOSStub_ae72 {
  strings:
    $key_ae72 = { fa 1a [2] 8e 02 [2] c9 00 [2] 8e 11 [2] c0 1d [2] cc 17 [2] db 1c [2] c0 52 [2] fd }

  condition:
    any of them
}