rule TTP_XOR_MULT_DOSStub_bc69 {
  strings:
    $key_bc69 = { e8 01 [2] 9c 19 [2] db 1b [2] 9c 0a [2] d2 06 [2] de 0c [2] c9 07 [2] d2 49 [2] ef }

  condition:
    any of them
}