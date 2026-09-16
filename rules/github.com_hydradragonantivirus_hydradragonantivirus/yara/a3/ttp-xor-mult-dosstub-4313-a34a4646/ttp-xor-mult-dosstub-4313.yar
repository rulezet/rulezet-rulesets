rule TTP_XOR_MULT_DOSStub_4313 {
  strings:
    $key_4313 = { 17 7b [2] 63 63 [2] 24 61 [2] 63 70 [2] 2d 7c [2] 21 76 [2] 36 7d [2] 2d 33 [2] 10 }

  condition:
    any of them
}