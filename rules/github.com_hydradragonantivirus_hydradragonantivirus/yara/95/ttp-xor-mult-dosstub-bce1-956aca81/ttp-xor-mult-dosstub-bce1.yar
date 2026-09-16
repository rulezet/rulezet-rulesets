rule TTP_XOR_MULT_DOSStub_bce1 {
  strings:
    $key_bce1 = { e8 89 [2] 9c 91 [2] db 93 [2] 9c 82 [2] d2 8e [2] de 84 [2] c9 8f [2] d2 c1 [2] ef }

  condition:
    any of them
}