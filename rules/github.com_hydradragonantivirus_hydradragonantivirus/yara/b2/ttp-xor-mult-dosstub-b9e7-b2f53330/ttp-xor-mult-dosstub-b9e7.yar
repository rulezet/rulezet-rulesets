rule TTP_XOR_MULT_DOSStub_b9e7 {
  strings:
    $key_b9e7 = { ed 8f [2] 99 97 [2] de 95 [2] 99 84 [2] d7 88 [2] db 82 [2] cc 89 [2] d7 c7 [2] ea }

  condition:
    any of them
}