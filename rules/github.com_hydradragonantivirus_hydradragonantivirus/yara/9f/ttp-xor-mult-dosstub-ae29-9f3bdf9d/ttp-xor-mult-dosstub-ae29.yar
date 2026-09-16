rule TTP_XOR_MULT_DOSStub_ae29 {
  strings:
    $key_ae29 = { fa 41 [2] 8e 59 [2] c9 5b [2] 8e 4a [2] c0 46 [2] cc 4c [2] db 47 [2] c0 09 [2] fd }

  condition:
    any of them
}