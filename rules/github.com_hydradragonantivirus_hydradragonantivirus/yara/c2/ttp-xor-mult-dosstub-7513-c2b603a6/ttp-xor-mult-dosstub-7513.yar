rule TTP_XOR_MULT_DOSStub_7513 {
  strings:
    $key_7513 = { 21 7b [2] 55 63 [2] 12 61 [2] 55 70 [2] 1b 7c [2] 17 76 [2] 00 7d [2] 1b 33 [2] 26 }

  condition:
    any of them
}