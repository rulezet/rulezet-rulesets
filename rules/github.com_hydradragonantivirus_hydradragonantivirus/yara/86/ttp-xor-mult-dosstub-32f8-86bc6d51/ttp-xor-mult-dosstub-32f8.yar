rule TTP_XOR_MULT_DOSStub_32f8 {
  strings:
    $key_32f8 = { 66 90 [2] 12 88 [2] 55 8a [2] 12 9b [2] 5c 97 [2] 50 9d [2] 47 96 [2] 5c d8 [2] 61 }

  condition:
    any of them
}