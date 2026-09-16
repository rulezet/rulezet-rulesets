rule TTP_XOR_MULT_DOSStub_b9e1 {
  strings:
    $key_b9e1 = { ed 89 [2] 99 91 [2] de 93 [2] 99 82 [2] d7 8e [2] db 84 [2] cc 8f [2] d7 c1 [2] ea }

  condition:
    any of them
}