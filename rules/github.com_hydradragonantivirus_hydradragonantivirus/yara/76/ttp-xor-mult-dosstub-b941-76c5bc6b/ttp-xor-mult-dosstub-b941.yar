rule TTP_XOR_MULT_DOSStub_b941 {
  strings:
    $key_b941 = { ed 29 [2] 99 31 [2] de 33 [2] 99 22 [2] d7 2e [2] db 24 [2] cc 2f [2] d7 61 [2] ea }

  condition:
    any of them
}