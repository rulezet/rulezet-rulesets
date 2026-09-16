rule TTP_XOR_MULT_DOSStub_7529 {
  strings:
    $key_7529 = { 21 41 [2] 55 59 [2] 12 5b [2] 55 4a [2] 1b 46 [2] 17 4c [2] 00 47 [2] 1b 09 [2] 26 }

  condition:
    any of them
}