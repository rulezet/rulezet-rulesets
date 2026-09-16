rule TTP_XOR_MULT_DOSStub_b97a {
  strings:
    $key_b97a = { ed 12 [2] 99 0a [2] de 08 [2] 99 19 [2] d7 15 [2] db 1f [2] cc 14 [2] d7 5a [2] ea }

  condition:
    any of them
}