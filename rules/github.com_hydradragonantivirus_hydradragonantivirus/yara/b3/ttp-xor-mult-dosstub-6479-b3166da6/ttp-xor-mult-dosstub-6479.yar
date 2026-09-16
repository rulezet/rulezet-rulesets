rule TTP_XOR_MULT_DOSStub_6479 {
  strings:
    $key_6479 = { 30 11 [2] 44 09 [2] 03 0b [2] 44 1a [2] 0a 16 [2] 06 1c [2] 11 17 [2] 0a 59 [2] 37 }

  condition:
    any of them
}