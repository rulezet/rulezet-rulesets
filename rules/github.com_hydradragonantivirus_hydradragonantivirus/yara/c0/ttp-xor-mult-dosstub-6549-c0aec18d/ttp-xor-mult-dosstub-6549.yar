rule TTP_XOR_MULT_DOSStub_6549 {
  strings:
    $key_6549 = { 31 21 [2] 45 39 [2] 02 3b [2] 45 2a [2] 0b 26 [2] 07 2c [2] 10 27 [2] 0b 69 [2] 36 }

  condition:
    any of them
}