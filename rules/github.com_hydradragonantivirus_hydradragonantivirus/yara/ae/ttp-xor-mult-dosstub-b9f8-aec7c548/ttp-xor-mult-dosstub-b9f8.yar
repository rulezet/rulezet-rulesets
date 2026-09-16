rule TTP_XOR_MULT_DOSStub_b9f8 {
  strings:
    $key_b9f8 = { ed 90 [2] 99 88 [2] de 8a [2] 99 9b [2] d7 97 [2] db 9d [2] cc 96 [2] d7 d8 [2] ea }

  condition:
    any of them
}