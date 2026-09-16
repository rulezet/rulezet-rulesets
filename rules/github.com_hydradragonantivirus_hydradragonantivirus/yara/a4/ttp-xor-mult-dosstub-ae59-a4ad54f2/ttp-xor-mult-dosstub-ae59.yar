rule TTP_XOR_MULT_DOSStub_ae59 {
  strings:
    $key_ae59 = { fa 31 [2] 8e 29 [2] c9 2b [2] 8e 3a [2] c0 36 [2] cc 3c [2] db 37 [2] c0 79 [2] fd }

  condition:
    any of them
}