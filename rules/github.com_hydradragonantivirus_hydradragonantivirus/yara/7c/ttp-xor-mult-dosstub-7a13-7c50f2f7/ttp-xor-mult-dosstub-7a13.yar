rule TTP_XOR_MULT_DOSStub_7a13 {
  strings:
    $key_7a13 = { 2e 7b [2] 5a 63 [2] 1d 61 [2] 5a 70 [2] 14 7c [2] 18 76 [2] 0f 7d [2] 14 33 [2] 29 }

  condition:
    any of them
}