rule TTP_XOR_MULT_DOSStub_b92a {
  strings:
    $key_b92a = { ed 42 [2] 99 5a [2] de 58 [2] 99 49 [2] d7 45 [2] db 4f [2] cc 44 [2] d7 0a [2] ea }

  condition:
    any of them
}