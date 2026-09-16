rule TTP_XOR_MULT_DOSStub_bcf4 {
  strings:
    $key_bcf4 = { e8 9c [2] 9c 84 [2] db 86 [2] 9c 97 [2] d2 9b [2] de 91 [2] c9 9a [2] d2 d4 [2] ef }

  condition:
    any of them
}