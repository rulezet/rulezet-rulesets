rule TTP_XOR_MULT_DOSStub_b94d {
  strings:
    $key_b94d = { ed 25 [2] 99 3d [2] de 3f [2] 99 2e [2] d7 22 [2] db 28 [2] cc 23 [2] d7 6d [2] ea }

  condition:
    any of them
}