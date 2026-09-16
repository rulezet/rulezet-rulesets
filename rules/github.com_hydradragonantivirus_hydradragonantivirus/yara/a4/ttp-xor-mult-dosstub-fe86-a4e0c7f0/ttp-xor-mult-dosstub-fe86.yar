rule TTP_XOR_MULT_DOSStub_fe86 {
  strings:
    $key_fe86 = { aa ee [2] de f6 [2] 99 f4 [2] de e5 [2] 90 e9 [2] 9c e3 [2] 8b e8 [2] 90 a6 [2] ad }

  condition:
    any of them
}