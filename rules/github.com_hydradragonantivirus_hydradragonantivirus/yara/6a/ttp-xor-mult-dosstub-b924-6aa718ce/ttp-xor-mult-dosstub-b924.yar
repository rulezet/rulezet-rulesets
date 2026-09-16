rule TTP_XOR_MULT_DOSStub_b924 {
  strings:
    $key_b924 = { ed 4c [2] 99 54 [2] de 56 [2] 99 47 [2] d7 4b [2] db 41 [2] cc 4a [2] d7 04 [2] ea }

  condition:
    any of them
}