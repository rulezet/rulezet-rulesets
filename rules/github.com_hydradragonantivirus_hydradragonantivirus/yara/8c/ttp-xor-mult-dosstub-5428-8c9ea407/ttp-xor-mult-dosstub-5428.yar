rule TTP_XOR_MULT_DOSStub_5428 {
  strings:
    $key_5428 = { 00 40 [2] 74 58 [2] 33 5a [2] 74 4b [2] 3a 47 [2] 36 4d [2] 21 46 [2] 3a 08 [2] 07 }

  condition:
    any of them
}