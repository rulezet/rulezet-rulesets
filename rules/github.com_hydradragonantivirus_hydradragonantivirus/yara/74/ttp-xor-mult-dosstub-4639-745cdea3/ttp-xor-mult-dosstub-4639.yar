rule TTP_XOR_MULT_DOSStub_4639 {
  strings:
    $key_4639 = { 12 51 [2] 66 49 [2] 21 4b [2] 66 5a [2] 28 56 [2] 24 5c [2] 33 57 [2] 28 19 [2] 15 }

  condition:
    any of them
}