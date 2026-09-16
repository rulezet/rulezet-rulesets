rule TTP_XOR_MULT_DOSStub_b9fe {
  strings:
    $key_b9fe = { ed 96 [2] 99 8e [2] de 8c [2] 99 9d [2] d7 91 [2] db 9b [2] cc 90 [2] d7 de [2] ea }

  condition:
    any of them
}