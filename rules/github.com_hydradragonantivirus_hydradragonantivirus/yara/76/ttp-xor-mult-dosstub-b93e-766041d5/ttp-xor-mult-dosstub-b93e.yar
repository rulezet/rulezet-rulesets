rule TTP_XOR_MULT_DOSStub_b93e {
  strings:
    $key_b93e = { ed 56 [2] 99 4e [2] de 4c [2] 99 5d [2] d7 51 [2] db 5b [2] cc 50 [2] d7 1e [2] ea }

  condition:
    any of them
}