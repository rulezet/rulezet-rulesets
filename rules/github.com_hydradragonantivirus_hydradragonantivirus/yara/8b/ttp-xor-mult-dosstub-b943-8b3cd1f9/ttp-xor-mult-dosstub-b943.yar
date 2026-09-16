rule TTP_XOR_MULT_DOSStub_b943 {
  strings:
    $key_b943 = { ed 2b [2] 99 33 [2] de 31 [2] 99 20 [2] d7 2c [2] db 26 [2] cc 2d [2] d7 63 [2] ea }

  condition:
    any of them
}