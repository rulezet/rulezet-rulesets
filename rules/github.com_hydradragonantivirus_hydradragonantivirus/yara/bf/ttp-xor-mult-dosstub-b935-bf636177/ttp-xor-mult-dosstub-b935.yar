rule TTP_XOR_MULT_DOSStub_b935 {
  strings:
    $key_b935 = { ed 5d [2] 99 45 [2] de 47 [2] 99 56 [2] d7 5a [2] db 50 [2] cc 5b [2] d7 15 [2] ea }

  condition:
    any of them
}