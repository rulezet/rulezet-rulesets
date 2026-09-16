rule TTP_XOR_MULT_DOSStub_ae44 {
  strings:
    $key_ae44 = { fa 2c [2] 8e 34 [2] c9 36 [2] 8e 27 [2] c0 2b [2] cc 21 [2] db 2a [2] c0 64 [2] fd }

  condition:
    any of them
}