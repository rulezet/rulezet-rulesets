rule TTP_XOR_MULT_DOSStub_6465 {
  strings:
    $key_6465 = { 30 0d [2] 44 15 [2] 03 17 [2] 44 06 [2] 0a 0a [2] 06 00 [2] 11 0b [2] 0a 45 [2] 37 }

  condition:
    any of them
}