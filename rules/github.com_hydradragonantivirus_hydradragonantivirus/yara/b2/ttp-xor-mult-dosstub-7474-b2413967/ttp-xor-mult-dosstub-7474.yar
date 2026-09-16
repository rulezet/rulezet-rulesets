rule TTP_XOR_MULT_DOSStub_7474 {
  strings:
    $key_7474 = { 20 1c [2] 54 04 [2] 13 06 [2] 54 17 [2] 1a 1b [2] 16 11 [2] 01 1a [2] 1a 54 [2] 27 }

  condition:
    any of them
}