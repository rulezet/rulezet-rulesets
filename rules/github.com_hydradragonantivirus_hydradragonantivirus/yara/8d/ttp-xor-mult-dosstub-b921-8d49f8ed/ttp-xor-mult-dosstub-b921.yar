rule TTP_XOR_MULT_DOSStub_b921 {
  strings:
    $key_b921 = { ed 49 [2] 99 51 [2] de 53 [2] 99 42 [2] d7 4e [2] db 44 [2] cc 4f [2] d7 01 [2] ea }

  condition:
    any of them
}