rule TTP_XOR_MULT_DOSStub_0532 {
  strings:
    $key_0532 = { 51 5a [2] 25 42 [2] 62 40 [2] 25 51 [2] 6b 5d [2] 67 57 [2] 70 5c [2] 6b 12 [2] 56 }

  condition:
    any of them
}