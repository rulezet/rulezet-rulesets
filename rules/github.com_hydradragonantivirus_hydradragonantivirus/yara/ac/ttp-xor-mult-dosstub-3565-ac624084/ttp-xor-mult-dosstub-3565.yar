rule TTP_XOR_MULT_DOSStub_3565 {
  strings:
    $key_3565 = { 61 0d [2] 15 15 [2] 52 17 [2] 15 06 [2] 5b 0a [2] 57 00 [2] 40 0b [2] 5b 45 [2] 66 }

  condition:
    any of them
}