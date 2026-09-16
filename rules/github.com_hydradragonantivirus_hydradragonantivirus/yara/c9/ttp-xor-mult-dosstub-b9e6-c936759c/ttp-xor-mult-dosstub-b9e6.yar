rule TTP_XOR_MULT_DOSStub_b9e6 {
  strings:
    $key_b9e6 = { ed 8e [2] 99 96 [2] de 94 [2] 99 85 [2] d7 89 [2] db 83 [2] cc 88 [2] d7 c6 [2] ea }

  condition:
    any of them
}