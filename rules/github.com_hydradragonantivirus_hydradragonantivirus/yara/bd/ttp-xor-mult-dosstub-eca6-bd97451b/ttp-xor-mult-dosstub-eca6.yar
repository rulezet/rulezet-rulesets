rule TTP_XOR_MULT_DOSStub_eca6 {
  strings:
    $key_eca6 = { b8 ce [2] cc d6 [2] 8b d4 [2] cc c5 [2] 82 c9 [2] 8e c3 [2] 99 c8 [2] 82 86 [2] bf }

  condition:
    any of them
}