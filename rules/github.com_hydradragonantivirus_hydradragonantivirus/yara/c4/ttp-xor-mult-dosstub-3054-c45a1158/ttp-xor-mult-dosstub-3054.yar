rule TTP_XOR_MULT_DOSStub_3054 {
  strings:
    $key_3054 = { 64 3c [2] 10 24 [2] 57 26 [2] 10 37 [2] 5e 3b [2] 52 31 [2] 45 3a [2] 5e 74 [2] 63 }

  condition:
    any of them
}