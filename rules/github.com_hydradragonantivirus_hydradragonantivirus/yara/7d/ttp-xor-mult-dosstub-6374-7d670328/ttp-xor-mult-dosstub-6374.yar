rule TTP_XOR_MULT_DOSStub_6374 {
  strings:
    $key_6374 = { 37 1c [2] 43 04 [2] 04 06 [2] 43 17 [2] 0d 1b [2] 01 11 [2] 16 1a [2] 0d 54 [2] 30 }

  condition:
    any of them
}