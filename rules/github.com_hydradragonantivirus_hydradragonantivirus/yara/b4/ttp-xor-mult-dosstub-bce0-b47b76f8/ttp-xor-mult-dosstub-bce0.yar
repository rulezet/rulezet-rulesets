rule TTP_XOR_MULT_DOSStub_bce0 {
  strings:
    $key_bce0 = { e8 88 [2] 9c 90 [2] db 92 [2] 9c 83 [2] d2 8f [2] de 85 [2] c9 8e [2] d2 c0 [2] ef }

  condition:
    any of them
}