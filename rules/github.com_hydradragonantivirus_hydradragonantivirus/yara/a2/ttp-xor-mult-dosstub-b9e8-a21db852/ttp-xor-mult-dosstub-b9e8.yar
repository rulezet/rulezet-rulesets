rule TTP_XOR_MULT_DOSStub_b9e8 {
  strings:
    $key_b9e8 = { ed 80 [2] 99 98 [2] de 9a [2] 99 8b [2] d7 87 [2] db 8d [2] cc 86 [2] d7 c8 [2] ea }

  condition:
    any of them
}