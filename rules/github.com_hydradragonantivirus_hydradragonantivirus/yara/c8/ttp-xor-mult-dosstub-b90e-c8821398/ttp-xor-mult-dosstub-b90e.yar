rule TTP_XOR_MULT_DOSStub_b90e {
  strings:
    $key_b90e = { ed 66 [2] 99 7e [2] de 7c [2] 99 6d [2] d7 61 [2] db 6b [2] cc 60 [2] d7 2e [2] ea }

  condition:
    any of them
}