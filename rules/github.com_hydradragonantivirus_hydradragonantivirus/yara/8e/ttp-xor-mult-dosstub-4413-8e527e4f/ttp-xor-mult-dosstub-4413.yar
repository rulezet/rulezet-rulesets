rule TTP_XOR_MULT_DOSStub_4413 {
  strings:
    $key_4413 = { 10 7b [2] 64 63 [2] 23 61 [2] 64 70 [2] 2a 7c [2] 26 76 [2] 31 7d [2] 2a 33 [2] 17 }

  condition:
    any of them
}