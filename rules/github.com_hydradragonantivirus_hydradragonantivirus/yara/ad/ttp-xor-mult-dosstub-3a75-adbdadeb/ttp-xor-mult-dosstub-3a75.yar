rule TTP_XOR_MULT_DOSStub_3a75 {
  strings:
    $key_3a75 = { 6e 1d [2] 1a 05 [2] 5d 07 [2] 1a 16 [2] 54 1a [2] 58 10 [2] 4f 1b [2] 54 55 [2] 69 }

  condition:
    any of them
}