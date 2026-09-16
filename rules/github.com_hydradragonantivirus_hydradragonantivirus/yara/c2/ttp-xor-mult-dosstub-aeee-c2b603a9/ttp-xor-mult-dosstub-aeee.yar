rule TTP_XOR_MULT_DOSStub_aeee {
  strings:
    $key_aeee = { fa 86 [2] 8e 9e [2] c9 9c [2] 8e 8d [2] c0 81 [2] cc 8b [2] db 80 [2] c0 ce [2] fd }

  condition:
    any of them
}