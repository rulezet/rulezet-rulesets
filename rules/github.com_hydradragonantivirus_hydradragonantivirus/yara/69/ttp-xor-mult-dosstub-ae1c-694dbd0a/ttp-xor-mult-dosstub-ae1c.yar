rule TTP_XOR_MULT_DOSStub_ae1c {
  strings:
    $key_ae1c = { fa 74 [2] 8e 6c [2] c9 6e [2] 8e 7f [2] c0 73 [2] cc 79 [2] db 72 [2] c0 3c [2] fd }

  condition:
    any of them
}