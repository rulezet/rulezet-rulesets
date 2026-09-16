rule TTP_XOR_MULT_DOSStub_17f8 {
  strings:
    $key_17f8 = { 43 90 [2] 37 88 [2] 70 8a [2] 37 9b [2] 79 97 [2] 75 9d [2] 62 96 [2] 79 d8 [2] 44 }

  condition:
    any of them
}