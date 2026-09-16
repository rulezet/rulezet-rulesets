rule TTP_XOR_MULT_DOSStub_b955 {
  strings:
    $key_b955 = { ed 3d [2] 99 25 [2] de 27 [2] 99 36 [2] d7 3a [2] db 30 [2] cc 3b [2] d7 75 [2] ea }

  condition:
    any of them
}