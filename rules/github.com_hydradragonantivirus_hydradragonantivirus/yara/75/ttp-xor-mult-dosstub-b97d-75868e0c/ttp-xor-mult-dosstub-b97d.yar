rule TTP_XOR_MULT_DOSStub_b97d {
  strings:
    $key_b97d = { ed 15 [2] 99 0d [2] de 0f [2] 99 1e [2] d7 12 [2] db 18 [2] cc 13 [2] d7 5d [2] ea }

  condition:
    any of them
}