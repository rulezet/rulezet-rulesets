rule TTP_XOR_MULT_DOSStub_1af8 {
  strings:
    $key_1af8 = { 4e 90 [2] 3a 88 [2] 7d 8a [2] 3a 9b [2] 74 97 [2] 78 9d [2] 6f 96 [2] 74 d8 [2] 49 }

  condition:
    any of them
}