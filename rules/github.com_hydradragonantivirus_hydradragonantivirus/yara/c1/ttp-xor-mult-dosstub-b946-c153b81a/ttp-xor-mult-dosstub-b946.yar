rule TTP_XOR_MULT_DOSStub_b946 {
  strings:
    $key_b946 = { ed 2e [2] 99 36 [2] de 34 [2] 99 25 [2] d7 29 [2] db 23 [2] cc 28 [2] d7 66 [2] ea }

  condition:
    any of them
}