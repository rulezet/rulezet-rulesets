rule TTP_XOR_MULT_DOSStub_36f8 {
  strings:
    $key_36f8 = { 62 90 [2] 16 88 [2] 51 8a [2] 16 9b [2] 58 97 [2] 54 9d [2] 43 96 [2] 58 d8 [2] 65 }

  condition:
    any of them
}