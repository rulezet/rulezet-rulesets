rule TTP_XOR_MULT_DOSStub_ae45 {
  strings:
    $key_ae45 = { fa 2d [2] 8e 35 [2] c9 37 [2] 8e 26 [2] c0 2a [2] cc 20 [2] db 2b [2] c0 65 [2] fd }

  condition:
    any of them
}