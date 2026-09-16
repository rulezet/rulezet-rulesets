rule TTP_XOR_MULT_DOSStub_b94b {
  strings:
    $key_b94b = { ed 23 [2] 99 3b [2] de 39 [2] 99 28 [2] d7 24 [2] db 2e [2] cc 25 [2] d7 6b [2] ea }

  condition:
    any of them
}