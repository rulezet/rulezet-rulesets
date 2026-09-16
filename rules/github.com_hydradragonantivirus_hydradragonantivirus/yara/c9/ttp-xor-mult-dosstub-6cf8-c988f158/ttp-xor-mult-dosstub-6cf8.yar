rule TTP_XOR_MULT_DOSStub_6cf8 {
  strings:
    $key_6cf8 = { 38 90 [2] 4c 88 [2] 0b 8a [2] 4c 9b [2] 02 97 [2] 0e 9d [2] 19 96 [2] 02 d8 [2] 3f }

  condition:
    any of them
}