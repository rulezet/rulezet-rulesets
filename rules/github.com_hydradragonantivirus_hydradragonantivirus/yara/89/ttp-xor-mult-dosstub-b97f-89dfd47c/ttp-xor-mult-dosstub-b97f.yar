rule TTP_XOR_MULT_DOSStub_b97f {
  strings:
    $key_b97f = { ed 17 [2] 99 0f [2] de 0d [2] 99 1c [2] d7 10 [2] db 1a [2] cc 11 [2] d7 5f [2] ea }

  condition:
    any of them
}