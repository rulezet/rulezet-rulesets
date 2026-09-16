rule TTP_XOR_MULT_DOSStub_71f8 {
  strings:
    $key_71f8 = { 25 90 [2] 51 88 [2] 16 8a [2] 51 9b [2] 1f 97 [2] 13 9d [2] 04 96 [2] 1f d8 [2] 22 }

  condition:
    any of them
}