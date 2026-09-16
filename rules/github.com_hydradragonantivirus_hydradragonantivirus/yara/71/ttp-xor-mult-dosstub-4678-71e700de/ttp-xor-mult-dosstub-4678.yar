rule TTP_XOR_MULT_DOSStub_4678 {
  strings:
    $key_4678 = { 12 10 [2] 66 08 [2] 21 0a [2] 66 1b [2] 28 17 [2] 24 1d [2] 33 16 [2] 28 58 [2] 15 }

  condition:
    any of them
}