rule TTP_XOR_MULT_DOSStub_2679 {
  strings:
    $key_2679 = { 72 11 [2] 06 09 [2] 41 0b [2] 06 1a [2] 48 16 [2] 44 1c [2] 53 17 [2] 48 59 [2] 75 }

  condition:
    any of them
}