rule TTP_XOR_MULT_DOSStub_bc0a {
  strings:
    $key_bc0a = { e8 62 [2] 9c 7a [2] db 78 [2] 9c 69 [2] d2 65 [2] de 6f [2] c9 64 [2] d2 2a [2] ef }

  condition:
    any of them
}