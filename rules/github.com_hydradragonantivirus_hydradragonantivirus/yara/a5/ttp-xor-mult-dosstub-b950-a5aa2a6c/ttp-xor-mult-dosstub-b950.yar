rule TTP_XOR_MULT_DOSStub_b950 {
  strings:
    $key_b950 = { ed 38 [2] 99 20 [2] de 22 [2] 99 33 [2] d7 3f [2] db 35 [2] cc 3e [2] d7 70 [2] ea }

  condition:
    any of them
}