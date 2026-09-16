rule TTP_XOR_MULT_DOSStub_1345 {
  strings:
    $key_1345 = { 47 2d [2] 33 35 [2] 74 37 [2] 33 26 [2] 7d 2a [2] 71 20 [2] 66 2b [2] 7d 65 [2] 40 }

  condition:
    any of them
}