rule TTP_XOR_MULT_DOSStub_b92e {
  strings:
    $key_b92e = { ed 46 [2] 99 5e [2] de 5c [2] 99 4d [2] d7 41 [2] db 4b [2] cc 40 [2] d7 0e [2] ea }

  condition:
    any of them
}