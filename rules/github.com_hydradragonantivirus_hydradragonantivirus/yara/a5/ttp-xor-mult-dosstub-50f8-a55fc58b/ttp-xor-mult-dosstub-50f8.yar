rule TTP_XOR_MULT_DOSStub_50f8 {
  strings:
    $key_50f8 = { 04 90 [2] 70 88 [2] 37 8a [2] 70 9b [2] 3e 97 [2] 32 9d [2] 25 96 [2] 3e d8 [2] 03 }

  condition:
    any of them
}