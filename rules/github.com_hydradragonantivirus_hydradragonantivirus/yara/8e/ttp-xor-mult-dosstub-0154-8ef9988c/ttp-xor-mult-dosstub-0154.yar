rule TTP_XOR_MULT_DOSStub_0154 {
  strings:
    $key_0154 = { 55 3c [2] 21 24 [2] 66 26 [2] 21 37 [2] 6f 3b [2] 63 31 [2] 74 3a [2] 6f 74 [2] 52 }

  condition:
    any of them
}