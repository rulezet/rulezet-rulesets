rule TTP_XOR_MULT_DOSStub_bc4b {
  strings:
    $key_bc4b = { e8 23 [2] 9c 3b [2] db 39 [2] 9c 28 [2] d2 24 [2] de 2e [2] c9 25 [2] d2 6b [2] ef }

  condition:
    any of them
}