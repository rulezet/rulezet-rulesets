rule TTP_XOR_MULT_DOSStub_ae3c {
  strings:
    $key_ae3c = { fa 54 [2] 8e 4c [2] c9 4e [2] 8e 5f [2] c0 53 [2] cc 59 [2] db 52 [2] c0 1c [2] fd }

  condition:
    any of them
}