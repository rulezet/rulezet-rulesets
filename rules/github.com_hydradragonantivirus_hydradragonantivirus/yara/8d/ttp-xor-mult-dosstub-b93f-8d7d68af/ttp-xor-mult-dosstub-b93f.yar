rule TTP_XOR_MULT_DOSStub_b93f {
  strings:
    $key_b93f = { ed 57 [2] 99 4f [2] de 4d [2] 99 5c [2] d7 50 [2] db 5a [2] cc 51 [2] d7 1f [2] ea }

  condition:
    any of them
}