rule TTP_XOR_MULT_DOSStub_6365 {
  strings:
    $key_6365 = { 37 0d [2] 43 15 [2] 04 17 [2] 43 06 [2] 0d 0a [2] 01 00 [2] 16 0b [2] 0d 45 [2] 30 }

  condition:
    any of them
}