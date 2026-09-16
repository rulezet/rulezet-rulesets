rule TTP_XOR_MULT_DOSStub_6464 {
  strings:
    $key_6464 = { 30 0c [2] 44 14 [2] 03 16 [2] 44 07 [2] 0a 0b [2] 06 01 [2] 11 0a [2] 0a 44 [2] 37 }

  condition:
    any of them
}