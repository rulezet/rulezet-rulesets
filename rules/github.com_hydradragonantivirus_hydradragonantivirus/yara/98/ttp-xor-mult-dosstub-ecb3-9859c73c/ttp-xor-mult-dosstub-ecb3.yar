rule TTP_XOR_MULT_DOSStub_ecb3 {
  strings:
    $key_ecb3 = { b8 db [2] cc c3 [2] 8b c1 [2] cc d0 [2] 82 dc [2] 8e d6 [2] 99 dd [2] 82 93 [2] bf }

  condition:
    any of them
}