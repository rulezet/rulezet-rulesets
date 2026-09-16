rule TTP_XOR_MULT_DOSStub_b9f6 {
  strings:
    $key_b9f6 = { ed 9e [2] 99 86 [2] de 84 [2] 99 95 [2] d7 99 [2] db 93 [2] cc 98 [2] d7 d6 [2] ea }

  condition:
    any of them
}