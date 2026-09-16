rule TTP_XOR_MULT_DOSStub_07f8 {
  strings:
    $key_07f8 = { 53 90 [2] 27 88 [2] 60 8a [2] 27 9b [2] 69 97 [2] 65 9d [2] 72 96 [2] 69 d8 [2] 54 }

  condition:
    any of them
}