rule TTP_XOR_MULT_DOSStub_b936 {
  strings:
    $key_b936 = { ed 5e [2] 99 46 [2] de 44 [2] 99 55 [2] d7 59 [2] db 53 [2] cc 58 [2] d7 16 [2] ea }

  condition:
    any of them
}