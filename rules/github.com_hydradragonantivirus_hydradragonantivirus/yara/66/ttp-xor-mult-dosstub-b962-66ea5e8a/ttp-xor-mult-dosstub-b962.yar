rule TTP_XOR_MULT_DOSStub_b962 {
  strings:
    $key_b962 = { ed 0a [2] 99 12 [2] de 10 [2] 99 01 [2] d7 0d [2] db 07 [2] cc 0c [2] d7 42 [2] ea }

  condition:
    any of them
}