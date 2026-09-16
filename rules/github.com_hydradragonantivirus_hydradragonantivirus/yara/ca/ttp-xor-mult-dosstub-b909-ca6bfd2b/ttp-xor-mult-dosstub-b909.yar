rule TTP_XOR_MULT_DOSStub_b909 {
  strings:
    $key_b909 = { ed 61 [2] 99 79 [2] de 7b [2] 99 6a [2] d7 66 [2] db 6c [2] cc 67 [2] d7 29 [2] ea }

  condition:
    any of them
}