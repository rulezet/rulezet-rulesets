rule TTP_XOR_MULT_DOSStub_b9f4 {
  strings:
    $key_b9f4 = { ed 9c [2] 99 84 [2] de 86 [2] 99 97 [2] d7 9b [2] db 91 [2] cc 9a [2] d7 d4 [2] ea }

  condition:
    any of them
}