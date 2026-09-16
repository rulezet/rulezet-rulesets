rule TTP_XOR_MULT_DOSStub_bc79 {
  strings:
    $key_bc79 = { e8 11 [2] 9c 09 [2] db 0b [2] 9c 1a [2] d2 16 [2] de 1c [2] c9 17 [2] d2 59 [2] ef }

  condition:
    any of them
}