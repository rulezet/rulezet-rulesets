rule TTP_XOR_MULT_DOSStub_bc78 {
  strings:
    $key_bc78 = { e8 10 [2] 9c 08 [2] db 0a [2] 9c 1b [2] d2 17 [2] de 1d [2] c9 16 [2] d2 58 [2] ef }

  condition:
    any of them
}