rule TTP_XOR_MULT_DOSStub_3336 {
  strings:
    $key_3336 = { 67 5e [2] 13 46 [2] 54 44 [2] 13 55 [2] 5d 59 [2] 51 53 [2] 46 58 [2] 5d 16 [2] 60 }

  condition:
    any of them
}