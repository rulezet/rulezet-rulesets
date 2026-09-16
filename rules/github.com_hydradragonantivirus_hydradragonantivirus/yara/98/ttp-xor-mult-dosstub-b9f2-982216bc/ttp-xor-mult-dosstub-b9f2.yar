rule TTP_XOR_MULT_DOSStub_b9f2 {
  strings:
    $key_b9f2 = { ed 9a [2] 99 82 [2] de 80 [2] 99 91 [2] d7 9d [2] db 97 [2] cc 9c [2] d7 d2 [2] ea }

  condition:
    any of them
}