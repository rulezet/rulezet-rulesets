rule TTP_XOR_MULT_DOSStub_7cba {
  strings:
    $key_7cba = { 28 d2 [2] 5c ca [2] 1b c8 [2] 5c d9 [2] 12 d5 [2] 1e df [2] 09 d4 [2] 12 9a [2] 2f }

  condition:
    any of them
}