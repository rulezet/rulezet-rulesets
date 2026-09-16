rule TTP_XOR_MULT_DOSStub_0539 {
  strings:
    $key_0539 = { 51 51 [2] 25 49 [2] 62 4b [2] 25 5a [2] 6b 56 [2] 67 5c [2] 70 57 [2] 6b 19 [2] 56 }

  condition:
    any of them
}