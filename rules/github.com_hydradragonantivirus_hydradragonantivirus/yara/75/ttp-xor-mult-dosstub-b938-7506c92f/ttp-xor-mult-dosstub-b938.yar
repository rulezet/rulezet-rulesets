rule TTP_XOR_MULT_DOSStub_b938 {
  strings:
    $key_b938 = { ed 50 [2] 99 48 [2] de 4a [2] 99 5b [2] d7 57 [2] db 5d [2] cc 56 [2] d7 18 [2] ea }

  condition:
    any of them
}