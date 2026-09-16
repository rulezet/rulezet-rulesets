rule TTP_XOR_MULT_DOSStub_6554 {
  strings:
    $key_6554 = { 31 3c [2] 45 24 [2] 02 26 [2] 45 37 [2] 0b 3b [2] 07 31 [2] 10 3a [2] 0b 74 [2] 36 }

  condition:
    any of them
}