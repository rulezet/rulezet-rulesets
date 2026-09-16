rule TTP_XOR_MULT_DOSStub_1a39 {
  strings:
    $key_1a39 = { 4e 51 [2] 3a 49 [2] 7d 4b [2] 3a 5a [2] 74 56 [2] 78 5c [2] 6f 57 [2] 74 19 [2] 49 }

  condition:
    any of them
}