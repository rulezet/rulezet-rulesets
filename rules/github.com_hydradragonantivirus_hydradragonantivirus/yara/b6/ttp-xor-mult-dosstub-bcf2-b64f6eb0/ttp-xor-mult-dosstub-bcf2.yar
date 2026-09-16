rule TTP_XOR_MULT_DOSStub_bcf2 {
  strings:
    $key_bcf2 = { e8 9a [2] 9c 82 [2] db 80 [2] 9c 91 [2] d2 9d [2] de 97 [2] c9 9c [2] d2 d2 [2] ef }

  condition:
    any of them
}