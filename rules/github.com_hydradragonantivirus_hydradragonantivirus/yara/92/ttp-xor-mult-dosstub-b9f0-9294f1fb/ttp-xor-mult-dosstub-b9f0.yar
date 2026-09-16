rule TTP_XOR_MULT_DOSStub_b9f0 {
  strings:
    $key_b9f0 = { ed 98 [2] 99 80 [2] de 82 [2] 99 93 [2] d7 9f [2] db 95 [2] cc 9e [2] d7 d0 [2] ea }

  condition:
    any of them
}