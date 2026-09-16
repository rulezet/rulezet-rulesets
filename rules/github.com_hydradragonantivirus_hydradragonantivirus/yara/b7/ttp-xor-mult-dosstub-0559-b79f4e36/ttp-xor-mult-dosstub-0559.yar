rule TTP_XOR_MULT_DOSStub_0559 {
  strings:
    $key_0559 = { 51 31 [2] 25 29 [2] 62 2b [2] 25 3a [2] 6b 36 [2] 67 3c [2] 70 37 [2] 6b 79 [2] 56 }

  condition:
    any of them
}