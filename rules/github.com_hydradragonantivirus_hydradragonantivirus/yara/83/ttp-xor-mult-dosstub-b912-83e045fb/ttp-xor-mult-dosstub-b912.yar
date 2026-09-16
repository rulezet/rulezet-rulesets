rule TTP_XOR_MULT_DOSStub_b912 {
  strings:
    $key_b912 = { ed 7a [2] 99 62 [2] de 60 [2] 99 71 [2] d7 7d [2] db 77 [2] cc 7c [2] d7 32 [2] ea }

  condition:
    any of them
}