rule TTP_XOR_MULT_DOSStub_b931 {
  strings:
    $key_b931 = { ed 59 [2] 99 41 [2] de 43 [2] 99 52 [2] d7 5e [2] db 54 [2] cc 5f [2] d7 11 [2] ea }

  condition:
    any of them
}