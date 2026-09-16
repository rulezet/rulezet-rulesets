rule TTP_XOR_MULT_DOSStub_b963 {
  strings:
    $key_b963 = { ed 0b [2] 99 13 [2] de 11 [2] 99 00 [2] d7 0c [2] db 06 [2] cc 0d [2] d7 43 [2] ea }

  condition:
    any of them
}