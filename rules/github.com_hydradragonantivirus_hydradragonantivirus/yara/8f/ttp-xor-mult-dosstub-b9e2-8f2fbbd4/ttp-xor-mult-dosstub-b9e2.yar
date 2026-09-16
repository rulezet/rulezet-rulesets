rule TTP_XOR_MULT_DOSStub_b9e2 {
  strings:
    $key_b9e2 = { ed 8a [2] 99 92 [2] de 90 [2] 99 81 [2] d7 8d [2] db 87 [2] cc 8c [2] d7 c2 [2] ea }

  condition:
    any of them
}