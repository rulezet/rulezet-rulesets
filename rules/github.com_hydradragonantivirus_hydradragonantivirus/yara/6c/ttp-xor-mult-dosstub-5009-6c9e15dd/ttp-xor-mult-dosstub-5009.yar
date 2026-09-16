rule TTP_XOR_MULT_DOSStub_5009 {
  strings:
    $key_5009 = { 04 61 [2] 70 79 [2] 37 7b [2] 70 6a [2] 3e 66 [2] 32 6c [2] 25 67 [2] 3e 29 [2] 03 }

  condition:
    any of them
}