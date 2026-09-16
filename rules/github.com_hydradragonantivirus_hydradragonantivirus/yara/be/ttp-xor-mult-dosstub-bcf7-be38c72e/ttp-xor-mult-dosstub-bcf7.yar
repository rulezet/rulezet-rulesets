rule TTP_XOR_MULT_DOSStub_bcf7 {
  strings:
    $key_bcf7 = { e8 9f [2] 9c 87 [2] db 85 [2] 9c 94 [2] d2 98 [2] de 92 [2] c9 99 [2] d2 d7 [2] ef }

  condition:
    any of them
}