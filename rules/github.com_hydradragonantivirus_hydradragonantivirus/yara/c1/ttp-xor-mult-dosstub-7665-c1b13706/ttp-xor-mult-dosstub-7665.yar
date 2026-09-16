rule TTP_XOR_MULT_DOSStub_7665 {
  strings:
    $key_7665 = { 22 0d [2] 56 15 [2] 11 17 [2] 56 06 [2] 18 0a [2] 14 00 [2] 03 0b [2] 18 45 [2] 25 }

  condition:
    any of them
}