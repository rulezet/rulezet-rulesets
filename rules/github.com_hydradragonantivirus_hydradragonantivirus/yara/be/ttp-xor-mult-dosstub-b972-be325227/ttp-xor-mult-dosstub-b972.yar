rule TTP_XOR_MULT_DOSStub_b972 {
  strings:
    $key_b972 = { ed 1a [2] 99 02 [2] de 00 [2] 99 11 [2] d7 1d [2] db 17 [2] cc 1c [2] d7 52 [2] ea }

  condition:
    any of them
}