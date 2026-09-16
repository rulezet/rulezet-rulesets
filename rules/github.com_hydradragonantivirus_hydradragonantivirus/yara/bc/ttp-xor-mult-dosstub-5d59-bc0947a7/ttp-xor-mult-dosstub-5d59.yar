rule TTP_XOR_MULT_DOSStub_5d59 {
  strings:
    $key_5d59 = { 09 31 [2] 7d 29 [2] 3a 2b [2] 7d 3a [2] 33 36 [2] 3f 3c [2] 28 37 [2] 33 79 [2] 0e }

  condition:
    any of them
}