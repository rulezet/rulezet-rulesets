rule TTP_XOR_MULT_DOSStub_ecba {
  strings:
    $key_ecba = { b8 d2 [2] cc ca [2] 8b c8 [2] cc d9 [2] 82 d5 [2] 8e df [2] 99 d4 [2] 82 9a [2] bf }

  condition:
    any of them
}