rule TTP_XOR_MULT_DOSStub_bce3 {
  strings:
    $key_bce3 = { e8 8b [2] 9c 93 [2] db 91 [2] 9c 80 [2] d2 8c [2] de 86 [2] c9 8d [2] d2 c3 [2] ef }

  condition:
    any of them
}