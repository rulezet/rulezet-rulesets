rule TTP_XOR_MULT_DOSStub_1364 {
  strings:
    $key_1364 = { 47 0c [2] 33 14 [2] 74 16 [2] 33 07 [2] 7d 0b [2] 71 01 [2] 66 0a [2] 7d 44 [2] 40 }

  condition:
    any of them
}