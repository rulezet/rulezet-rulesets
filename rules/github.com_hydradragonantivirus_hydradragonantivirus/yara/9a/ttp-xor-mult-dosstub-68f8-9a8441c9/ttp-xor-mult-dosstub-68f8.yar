rule TTP_XOR_MULT_DOSStub_68f8 {
  strings:
    $key_68f8 = { 3c 90 [2] 48 88 [2] 0f 8a [2] 48 9b [2] 06 97 [2] 0a 9d [2] 1d 96 [2] 06 d8 [2] 3b }

  condition:
    any of them
}