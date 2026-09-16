rule TTP_XOR_MULT_DOSStub_b9ee {
  strings:
    $key_b9ee = { ed 86 [2] 99 9e [2] de 9c [2] 99 8d [2] d7 81 [2] db 8b [2] cc 80 [2] d7 ce [2] ea }

  condition:
    any of them
}