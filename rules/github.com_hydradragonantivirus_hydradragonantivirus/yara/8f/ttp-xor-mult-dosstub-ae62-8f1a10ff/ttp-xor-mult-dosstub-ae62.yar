rule TTP_XOR_MULT_DOSStub_ae62 {
  strings:
    $key_ae62 = { fa 0a [2] 8e 12 [2] c9 10 [2] 8e 01 [2] c0 0d [2] cc 07 [2] db 0c [2] c0 42 [2] fd }

  condition:
    any of them
}