rule TTP_XOR_MULT_DOSStub_b95e {
  strings:
    $key_b95e = { ed 36 [2] 99 2e [2] de 2c [2] 99 3d [2] d7 31 [2] db 3b [2] cc 30 [2] d7 7e [2] ea }

  condition:
    any of them
}