rule TTP_XOR_MULT_DOSStub_ae38 {
  strings:
    $key_ae38 = { fa 50 [2] 8e 48 [2] c9 4a [2] 8e 5b [2] c0 57 [2] cc 5d [2] db 56 [2] c0 18 [2] fd }

  condition:
    any of them
}