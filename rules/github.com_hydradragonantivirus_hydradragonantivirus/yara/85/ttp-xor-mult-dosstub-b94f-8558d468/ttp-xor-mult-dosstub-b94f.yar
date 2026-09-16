rule TTP_XOR_MULT_DOSStub_b94f {
  strings:
    $key_b94f = { ed 27 [2] 99 3f [2] de 3d [2] 99 2c [2] d7 20 [2] db 2a [2] cc 21 [2] d7 6f [2] ea }

  condition:
    any of them
}