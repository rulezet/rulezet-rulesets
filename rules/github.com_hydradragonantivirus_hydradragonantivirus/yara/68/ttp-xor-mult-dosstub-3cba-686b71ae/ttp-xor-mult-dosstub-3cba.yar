rule TTP_XOR_MULT_DOSStub_3cba {
  strings:
    $key_3cba = { 68 d2 [2] 1c ca [2] 5b c8 [2] 1c d9 [2] 52 d5 [2] 5e df [2] 49 d4 [2] 52 9a [2] 6f }

  condition:
    any of them
}