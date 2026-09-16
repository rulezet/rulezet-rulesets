rule TTP_XOR_MULT_DOSStub_ae0e {
  strings:
    $key_ae0e = { fa 66 [2] 8e 7e [2] c9 7c [2] 8e 6d [2] c0 61 [2] cc 6b [2] db 60 [2] c0 2e [2] fd }

  condition:
    any of them
}