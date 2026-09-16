rule TTP_XOR_MULT_DOSStub_bcf5 {
  strings:
    $key_bcf5 = { e8 9d [2] 9c 85 [2] db 87 [2] 9c 96 [2] d2 9a [2] de 90 [2] c9 9b [2] d2 d5 [2] ef }

  condition:
    any of them
}