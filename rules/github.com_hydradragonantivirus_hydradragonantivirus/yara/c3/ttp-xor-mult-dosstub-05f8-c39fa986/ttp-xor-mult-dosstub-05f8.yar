rule TTP_XOR_MULT_DOSStub_05f8 {
  strings:
    $key_05f8 = { 51 90 [2] 25 88 [2] 62 8a [2] 25 9b [2] 6b 97 [2] 67 9d [2] 70 96 [2] 6b d8 [2] 56 }

  condition:
    any of them
}