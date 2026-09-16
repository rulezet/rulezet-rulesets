rule TTP_XOR_MULT_DOSStub_b947 {
  strings:
    $key_b947 = { ed 2f [2] 99 37 [2] de 35 [2] 99 24 [2] d7 28 [2] db 22 [2] cc 29 [2] d7 67 [2] ea }

  condition:
    any of them
}