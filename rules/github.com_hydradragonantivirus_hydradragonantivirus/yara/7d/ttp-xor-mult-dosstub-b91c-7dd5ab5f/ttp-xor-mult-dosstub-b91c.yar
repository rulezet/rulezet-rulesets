rule TTP_XOR_MULT_DOSStub_b91c {
  strings:
    $key_b91c = { ed 74 [2] 99 6c [2] de 6e [2] 99 7f [2] d7 73 [2] db 79 [2] cc 72 [2] d7 3c [2] ea }

  condition:
    any of them
}