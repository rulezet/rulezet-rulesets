rule TTP_XOR_MULT_DOSStub_b939 {
  strings:
    $key_b939 = { ed 51 [2] 99 49 [2] de 4b [2] 99 5a [2] d7 56 [2] db 5c [2] cc 57 [2] d7 19 [2] ea }

  condition:
    any of them
}