rule TTP_XOR_MULT_DOSStub_47f8 {
  strings:
    $key_47f8 = { 13 90 [2] 67 88 [2] 20 8a [2] 67 9b [2] 29 97 [2] 25 9d [2] 32 96 [2] 29 d8 [2] 14 }

  condition:
    any of them
}