rule TTP_XOR_MULT_DOSStub_7d59 {
  strings:
    $key_7d59 = { 29 31 [2] 5d 29 [2] 1a 2b [2] 5d 3a [2] 13 36 [2] 1f 3c [2] 08 37 [2] 13 79 [2] 2e }

  condition:
    any of them
}