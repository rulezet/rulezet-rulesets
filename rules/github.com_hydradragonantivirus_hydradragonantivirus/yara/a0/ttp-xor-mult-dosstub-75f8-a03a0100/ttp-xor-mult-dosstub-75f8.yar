rule TTP_XOR_MULT_DOSStub_75f8 {
  strings:
    $key_75f8 = { 21 90 [2] 55 88 [2] 12 8a [2] 55 9b [2] 1b 97 [2] 17 9d [2] 00 96 [2] 1b d8 [2] 26 }

  condition:
    any of them
}