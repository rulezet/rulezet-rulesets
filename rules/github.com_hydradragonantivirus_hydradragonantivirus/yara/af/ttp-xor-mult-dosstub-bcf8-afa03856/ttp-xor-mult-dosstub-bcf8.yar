rule TTP_XOR_MULT_DOSStub_bcf8 {
  strings:
    $key_bcf8 = { e8 90 [2] 9c 88 [2] db 8a [2] 9c 9b [2] d2 97 [2] de 9d [2] c9 96 [2] d2 d8 [2] ef }

  condition:
    any of them
}