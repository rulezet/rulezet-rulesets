rule TTP_XOR_MULT_DOSStub_00f8 {
  strings:
    $key_00f8 = { 54 90 [2] 20 88 [2] 67 8a [2] 20 9b [2] 6e 97 [2] 62 9d [2] 75 96 [2] 6e d8 [2] 53 }

  condition:
    any of them
}