rule TTP_XOR_MULT_DOSStub_b915 {
  strings:
    $key_b915 = { ed 7d [2] 99 65 [2] de 67 [2] 99 76 [2] d7 7a [2] db 70 [2] cc 7b [2] d7 35 [2] ea }

  condition:
    any of them
}