rule TTP_XOR_MULT_DOSStub_bce8 {
  strings:
    $key_bce8 = { e8 80 [2] 9c 98 [2] db 9a [2] 9c 8b [2] d2 87 [2] de 8d [2] c9 86 [2] d2 c8 [2] ef }

  condition:
    any of them
}