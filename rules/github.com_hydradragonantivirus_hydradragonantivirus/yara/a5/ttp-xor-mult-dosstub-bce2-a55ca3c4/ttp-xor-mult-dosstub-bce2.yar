rule TTP_XOR_MULT_DOSStub_bce2 {
  strings:
    $key_bce2 = { e8 8a [2] 9c 92 [2] db 90 [2] 9c 81 [2] d2 8d [2] de 87 [2] c9 8c [2] d2 c2 [2] ef }

  condition:
    any of them
}