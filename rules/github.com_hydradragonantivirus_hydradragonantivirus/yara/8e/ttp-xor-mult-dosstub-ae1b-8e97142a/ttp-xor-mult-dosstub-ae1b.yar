rule TTP_XOR_MULT_DOSStub_ae1b {
  strings:
    $key_ae1b = { fa 73 [2] 8e 6b [2] c9 69 [2] 8e 78 [2] c0 74 [2] cc 7e [2] db 75 [2] c0 3b [2] fd }

  condition:
    any of them
}