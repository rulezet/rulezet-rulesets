rule TTP_XOR_MULT_DOSStub_4cba {
  strings:
    $key_4cba = { 18 d2 [2] 6c ca [2] 2b c8 [2] 6c d9 [2] 22 d5 [2] 2e df [2] 39 d4 [2] 22 9a [2] 1f }

  condition:
    any of them
}