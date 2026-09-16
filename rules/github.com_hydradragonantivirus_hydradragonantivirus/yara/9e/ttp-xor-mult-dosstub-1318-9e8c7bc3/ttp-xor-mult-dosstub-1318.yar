rule TTP_XOR_MULT_DOSStub_1318 {
  strings:
    $key_1318 = { 47 70 [2] 33 68 [2] 74 6a [2] 33 7b [2] 7d 77 [2] 71 7d [2] 66 76 [2] 7d 38 [2] 40 }

  condition:
    any of them
}