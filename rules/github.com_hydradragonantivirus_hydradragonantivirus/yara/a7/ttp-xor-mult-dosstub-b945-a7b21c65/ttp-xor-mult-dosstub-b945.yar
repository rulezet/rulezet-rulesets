rule TTP_XOR_MULT_DOSStub_b945 {
  strings:
    $key_b945 = { ed 2d [2] 99 35 [2] de 37 [2] 99 26 [2] d7 2a [2] db 20 [2] cc 2b [2] d7 65 [2] ea }

  condition:
    any of them
}