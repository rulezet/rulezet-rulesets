rule TTP_XOR_MULT_DOSStub_b95b {
  strings:
    $key_b95b = { ed 33 [2] 99 2b [2] de 29 [2] 99 38 [2] d7 34 [2] db 3e [2] cc 35 [2] d7 7b [2] ea }

  condition:
    any of them
}