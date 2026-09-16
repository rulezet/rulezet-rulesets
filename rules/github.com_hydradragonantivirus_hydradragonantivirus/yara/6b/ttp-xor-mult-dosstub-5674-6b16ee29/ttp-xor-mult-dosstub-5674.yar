rule TTP_XOR_MULT_DOSStub_5674 {
  strings:
    $key_5674 = { 02 1c [2] 76 04 [2] 31 06 [2] 76 17 [2] 38 1b [2] 34 11 [2] 23 1a [2] 38 54 [2] 05 }

  condition:
    any of them
}