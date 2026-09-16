rule TTP_XOR_MULT_DOSStub_1759 {
  strings:
    $key_1759 = { 43 31 [2] 37 29 [2] 70 2b [2] 37 3a [2] 79 36 [2] 75 3c [2] 62 37 [2] 79 79 [2] 44 }

  condition:
    any of them
}