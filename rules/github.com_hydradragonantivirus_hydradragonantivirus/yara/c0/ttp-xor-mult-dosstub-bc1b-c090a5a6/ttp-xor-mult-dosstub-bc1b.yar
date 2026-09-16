rule TTP_XOR_MULT_DOSStub_bc1b {
  strings:
    $key_bc1b = { e8 73 [2] 9c 6b [2] db 69 [2] 9c 78 [2] d2 74 [2] de 7e [2] c9 75 [2] d2 3b [2] ef }

  condition:
    any of them
}