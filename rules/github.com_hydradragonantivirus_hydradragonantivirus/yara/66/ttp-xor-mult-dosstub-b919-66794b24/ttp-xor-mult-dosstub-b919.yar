rule TTP_XOR_MULT_DOSStub_b919 {
  strings:
    $key_b919 = { ed 71 [2] 99 69 [2] de 6b [2] 99 7a [2] d7 76 [2] db 7c [2] cc 77 [2] d7 39 [2] ea }

  condition:
    any of them
}