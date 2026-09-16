rule TTP_XOR_MULT_DOSStub_b902 {
  strings:
    $key_b902 = { ed 6a [2] 99 72 [2] de 70 [2] 99 61 [2] d7 6d [2] db 67 [2] cc 6c [2] d7 22 [2] ea }

  condition:
    any of them
}