rule TTP_XOR_MULT_DOSStub_2cf8 {
  strings:
    $key_2cf8 = { 78 90 [2] 0c 88 [2] 4b 8a [2] 0c 9b [2] 42 97 [2] 4e 9d [2] 59 96 [2] 42 d8 [2] 7f }

  condition:
    any of them
}