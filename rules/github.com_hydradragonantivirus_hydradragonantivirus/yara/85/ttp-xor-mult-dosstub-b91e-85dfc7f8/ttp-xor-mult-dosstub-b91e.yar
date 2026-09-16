rule TTP_XOR_MULT_DOSStub_b91e {
  strings:
    $key_b91e = { ed 76 [2] 99 6e [2] de 6c [2] 99 7d [2] d7 71 [2] db 7b [2] cc 70 [2] d7 3e [2] ea }

  condition:
    any of them
}