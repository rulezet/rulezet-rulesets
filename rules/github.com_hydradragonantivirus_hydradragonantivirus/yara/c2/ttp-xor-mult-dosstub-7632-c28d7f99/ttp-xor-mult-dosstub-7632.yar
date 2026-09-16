rule TTP_XOR_MULT_DOSStub_7632 {
  strings:
    $key_7632 = { 22 5a [2] 56 42 [2] 11 40 [2] 56 51 [2] 18 5d [2] 14 57 [2] 03 5c [2] 18 12 [2] 25 }

  condition:
    any of them
}