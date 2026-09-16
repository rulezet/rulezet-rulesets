rule TTP_XOR_MULT_DOSStub_3379 {
  strings:
    $key_3379 = { 67 11 [2] 13 09 [2] 54 0b [2] 13 1a [2] 5d 16 [2] 51 1c [2] 46 17 [2] 5d 59 [2] 60 }

  condition:
    any of them
}