rule TTP_XOR_MULT_DOSStub_1315 {
  strings:
    $key_1315 = { 47 7d [2] 33 65 [2] 74 67 [2] 33 76 [2] 7d 7a [2] 71 70 [2] 66 7b [2] 7d 35 [2] 40 }

  condition:
    any of them
}