rule TTP_XOR_MULT_DOSStub_5163 {
  strings:
    $key_5163 = { 05 0b [2] 71 13 [2] 36 11 [2] 71 00 [2] 3f 0c [2] 33 06 [2] 24 0d [2] 3f 43 [2] 02 }

  condition:
    any of them
}