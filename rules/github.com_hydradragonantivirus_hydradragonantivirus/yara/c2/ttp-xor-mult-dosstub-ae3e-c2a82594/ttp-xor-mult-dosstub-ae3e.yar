rule TTP_XOR_MULT_DOSStub_ae3e {
  strings:
    $key_ae3e = { fa 56 [2] 8e 4e [2] c9 4c [2] 8e 5d [2] c0 51 [2] cc 5b [2] db 50 [2] c0 1e [2] fd }

  condition:
    any of them
}