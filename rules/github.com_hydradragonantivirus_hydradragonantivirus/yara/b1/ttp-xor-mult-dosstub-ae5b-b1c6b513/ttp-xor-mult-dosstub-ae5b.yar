rule TTP_XOR_MULT_DOSStub_ae5b {
  strings:
    $key_ae5b = { fa 33 [2] 8e 2b [2] c9 29 [2] 8e 38 [2] c0 34 [2] cc 3e [2] db 35 [2] c0 7b [2] fd }

  condition:
    any of them
}