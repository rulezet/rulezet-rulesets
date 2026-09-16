rule TTP_XOR_MULT_DOSStub_b9e5 {
  strings:
    $key_b9e5 = { ed 8d [2] 99 95 [2] de 97 [2] 99 86 [2] d7 8a [2] db 80 [2] cc 8b [2] d7 c5 [2] ea }

  condition:
    any of them
}