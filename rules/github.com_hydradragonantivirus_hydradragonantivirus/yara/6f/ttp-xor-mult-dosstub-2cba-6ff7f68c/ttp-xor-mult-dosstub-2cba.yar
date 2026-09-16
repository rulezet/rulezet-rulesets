rule TTP_XOR_MULT_DOSStub_2cba {
  strings:
    $key_2cba = { 78 d2 [2] 0c ca [2] 4b c8 [2] 0c d9 [2] 42 d5 [2] 4e df [2] 59 d4 [2] 42 9a [2] 7f }

  condition:
    any of them
}