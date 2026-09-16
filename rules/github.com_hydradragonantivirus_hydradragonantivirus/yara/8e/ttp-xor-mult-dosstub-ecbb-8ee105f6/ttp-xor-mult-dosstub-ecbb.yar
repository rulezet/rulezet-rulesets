rule TTP_XOR_MULT_DOSStub_ecbb {
  strings:
    $key_ecbb = { b8 d3 [2] cc cb [2] 8b c9 [2] cc d8 [2] 82 d4 [2] 8e de [2] 99 d5 [2] 82 9b [2] bf }

  condition:
    any of them
}