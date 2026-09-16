rule TTP_XOR_MULT_DOSStub_bce7 {
  strings:
    $key_bce7 = { e8 8f [2] 9c 97 [2] db 95 [2] 9c 84 [2] d2 88 [2] de 82 [2] c9 89 [2] d2 c7 [2] ef }

  condition:
    any of them
}