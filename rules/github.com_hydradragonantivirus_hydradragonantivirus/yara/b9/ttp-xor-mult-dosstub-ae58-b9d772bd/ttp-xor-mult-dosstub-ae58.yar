rule TTP_XOR_MULT_DOSStub_ae58 {
  strings:
    $key_ae58 = { fa 30 [2] 8e 28 [2] c9 2a [2] 8e 3b [2] c0 37 [2] cc 3d [2] db 36 [2] c0 78 [2] fd }

  condition:
    any of them
}