rule TTP_XOR_MULT_DOSStub_7678 {
  strings:
    $key_7678 = { 22 10 [2] 56 08 [2] 11 0a [2] 56 1b [2] 18 17 [2] 14 1d [2] 03 16 [2] 18 58 [2] 25 }

  condition:
    any of them
}