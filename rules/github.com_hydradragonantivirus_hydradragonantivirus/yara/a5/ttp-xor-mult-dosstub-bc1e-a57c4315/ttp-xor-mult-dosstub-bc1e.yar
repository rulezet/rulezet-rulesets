rule TTP_XOR_MULT_DOSStub_bc1e {
  strings:
    $key_bc1e = { e8 76 [2] 9c 6e [2] db 6c [2] 9c 7d [2] d2 71 [2] de 7b [2] c9 70 [2] d2 3e [2] ef }

  condition:
    any of them
}