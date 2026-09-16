rule TTP_XOR_MULT_DOSStub_5d39 {
  strings:
    $key_5d39 = { 09 51 [2] 7d 49 [2] 3a 4b [2] 7d 5a [2] 33 56 [2] 3f 5c [2] 28 57 [2] 33 19 [2] 0e }

  condition:
    any of them
}