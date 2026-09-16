rule TTP_XOR_MULT_DOSStub_b94e {
  strings:
    $key_b94e = { ed 26 [2] 99 3e [2] de 3c [2] 99 2d [2] d7 21 [2] db 2b [2] cc 20 [2] d7 6e [2] ea }

  condition:
    any of them
}