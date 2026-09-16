rule TTP_XOR_MULT_DOSStub_ae25 {
  strings:
    $key_ae25 = { fa 4d [2] 8e 55 [2] c9 57 [2] 8e 46 [2] c0 4a [2] cc 40 [2] db 4b [2] c0 05 [2] fd }

  condition:
    any of them
}