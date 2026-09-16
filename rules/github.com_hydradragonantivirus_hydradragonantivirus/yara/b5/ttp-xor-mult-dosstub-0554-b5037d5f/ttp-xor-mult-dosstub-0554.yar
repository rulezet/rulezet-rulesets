rule TTP_XOR_MULT_DOSStub_0554 {
  strings:
    $key_0554 = { 51 3c [2] 25 24 [2] 62 26 [2] 25 37 [2] 6b 3b [2] 67 31 [2] 70 3a [2] 6b 74 [2] 56 }

  condition:
    any of them
}