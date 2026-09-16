rule TTP_XOR_MULT_DOSStub_b96e {
  strings:
    $key_b96e = { ed 06 [2] 99 1e [2] de 1c [2] 99 0d [2] d7 01 [2] db 0b [2] cc 00 [2] d7 4e [2] ea }

  condition:
    any of them
}