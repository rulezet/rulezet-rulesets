rule TTP_XOR_MULT_DOSStub_3713 {
  strings:
    $key_3713 = { 63 7b [2] 17 63 [2] 50 61 [2] 17 70 [2] 59 7c [2] 55 76 [2] 42 7d [2] 59 33 [2] 64 }

  condition:
    any of them
}