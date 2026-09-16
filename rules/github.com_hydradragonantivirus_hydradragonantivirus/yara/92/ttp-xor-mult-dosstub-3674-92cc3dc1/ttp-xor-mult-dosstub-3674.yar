rule TTP_XOR_MULT_DOSStub_3674 {
  strings:
    $key_3674 = { 62 1c [2] 16 04 [2] 51 06 [2] 16 17 [2] 58 1b [2] 54 11 [2] 43 1a [2] 58 54 [2] 65 }

  condition:
    any of them
}