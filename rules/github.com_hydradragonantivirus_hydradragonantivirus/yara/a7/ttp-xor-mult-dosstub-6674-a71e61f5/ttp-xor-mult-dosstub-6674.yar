rule TTP_XOR_MULT_DOSStub_6674 {
  strings:
    $key_6674 = { 32 1c [2] 46 04 [2] 01 06 [2] 46 17 [2] 08 1b [2] 04 11 [2] 13 1a [2] 08 54 [2] 35 }

  condition:
    any of them
}