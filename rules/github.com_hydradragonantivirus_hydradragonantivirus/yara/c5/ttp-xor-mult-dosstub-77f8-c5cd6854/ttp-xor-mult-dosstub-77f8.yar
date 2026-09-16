rule TTP_XOR_MULT_DOSStub_77f8 {
  strings:
    $key_77f8 = { 23 90 [2] 57 88 [2] 10 8a [2] 57 9b [2] 19 97 [2] 15 9d [2] 02 96 [2] 19 d8 [2] 24 }

  condition:
    any of them
}