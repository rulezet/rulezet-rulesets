rule TTP_XOR_MULT_DOSStub_b907 {
  strings:
    $key_b907 = { ed 6f [2] 99 77 [2] de 75 [2] 99 64 [2] d7 68 [2] db 62 [2] cc 69 [2] d7 27 [2] ea }

  condition:
    any of them
}