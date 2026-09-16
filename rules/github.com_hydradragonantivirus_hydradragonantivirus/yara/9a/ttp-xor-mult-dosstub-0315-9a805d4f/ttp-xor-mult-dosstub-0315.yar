rule TTP_XOR_MULT_DOSStub_0315 {
  strings:
    $key_0315 = { 57 7d [2] 23 65 [2] 64 67 [2] 23 76 [2] 6d 7a [2] 61 70 [2] 76 7b [2] 6d 35 [2] 50 }

  condition:
    any of them
}