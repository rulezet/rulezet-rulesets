rule TTP_XOR_MULT_DOSStub_0534 {
  strings:
    $key_0534 = { 51 5c [2] 25 44 [2] 62 46 [2] 25 57 [2] 6b 5b [2] 67 51 [2] 70 5a [2] 6b 14 [2] 56 }

  condition:
    any of them
}