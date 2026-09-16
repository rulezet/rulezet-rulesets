rule TTP_XOR_MULT_DOSStub_22f8 {
  strings:
    $key_22f8 = { 76 90 [2] 02 88 [2] 45 8a [2] 02 9b [2] 4c 97 [2] 40 9d [2] 57 96 [2] 4c d8 [2] 71 }

  condition:
    any of them
}