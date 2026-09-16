rule TTP_XOR_MULT_DOSStub_b910 {
  strings:
    $key_b910 = { ed 78 [2] 99 60 [2] de 62 [2] 99 73 [2] d7 7f [2] db 75 [2] cc 7e [2] d7 30 [2] ea }

  condition:
    any of them
}