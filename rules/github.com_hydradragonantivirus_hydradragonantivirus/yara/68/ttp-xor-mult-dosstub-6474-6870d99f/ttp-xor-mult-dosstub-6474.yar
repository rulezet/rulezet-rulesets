rule TTP_XOR_MULT_DOSStub_6474 {
  strings:
    $key_6474 = { 30 1c [2] 44 04 [2] 03 06 [2] 44 17 [2] 0a 1b [2] 06 11 [2] 11 1a [2] 0a 54 [2] 37 }

  condition:
    any of them
}