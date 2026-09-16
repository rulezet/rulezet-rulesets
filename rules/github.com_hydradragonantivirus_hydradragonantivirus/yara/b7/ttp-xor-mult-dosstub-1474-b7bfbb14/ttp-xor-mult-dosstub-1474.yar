rule TTP_XOR_MULT_DOSStub_1474 {
  strings:
    $key_1474 = { 40 1c [2] 34 04 [2] 73 06 [2] 34 17 [2] 7a 1b [2] 76 11 [2] 61 1a [2] 7a 54 [2] 47 }

  condition:
    any of them
}