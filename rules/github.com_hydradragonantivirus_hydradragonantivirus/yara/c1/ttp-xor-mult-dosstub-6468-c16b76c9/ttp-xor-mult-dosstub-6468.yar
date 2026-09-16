rule TTP_XOR_MULT_DOSStub_6468 {
  strings:
    $key_6468 = { 30 00 [2] 44 18 [2] 03 1a [2] 44 0b [2] 0a 07 [2] 06 0d [2] 11 06 [2] 0a 48 [2] 37 }

  condition:
    any of them
}