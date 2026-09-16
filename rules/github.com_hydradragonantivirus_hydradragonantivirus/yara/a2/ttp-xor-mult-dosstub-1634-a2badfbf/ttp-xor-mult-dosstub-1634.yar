rule TTP_XOR_MULT_DOSStub_1634 {
  strings:
    $key_1634 = { 42 5c [2] 36 44 [2] 71 46 [2] 36 57 [2] 78 5b [2] 74 51 [2] 63 5a [2] 78 14 [2] 45 }

  condition:
    any of them
}