rule TTP_XOR_MULT_DOSStub_0134 {
  strings:
    $key_0134 = { 55 5c [2] 21 44 [2] 66 46 [2] 21 57 [2] 6f 5b [2] 63 51 [2] 74 5a [2] 6f 14 [2] 52 }

  condition:
    any of them
}