rule TTP_XOR_MULT_DOSStub_b976 {
  strings:
    $key_b976 = { ed 1e [2] 99 06 [2] de 04 [2] 99 15 [2] d7 19 [2] db 13 [2] cc 18 [2] d7 56 [2] ea }

  condition:
    any of them
}