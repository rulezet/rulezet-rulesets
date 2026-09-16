rule TTP_XOR_MULT_DOSStub_b966 {
  strings:
    $key_b966 = { ed 0e [2] 99 16 [2] de 14 [2] 99 05 [2] d7 09 [2] db 03 [2] cc 08 [2] d7 46 [2] ea }

  condition:
    any of them
}