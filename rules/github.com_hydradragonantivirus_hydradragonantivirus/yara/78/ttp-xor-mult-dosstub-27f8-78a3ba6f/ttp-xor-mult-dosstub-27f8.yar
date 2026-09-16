rule TTP_XOR_MULT_DOSStub_27f8 {
  strings:
    $key_27f8 = { 73 90 [2] 07 88 [2] 40 8a [2] 07 9b [2] 49 97 [2] 45 9d [2] 52 96 [2] 49 d8 [2] 74 }

  condition:
    any of them
}