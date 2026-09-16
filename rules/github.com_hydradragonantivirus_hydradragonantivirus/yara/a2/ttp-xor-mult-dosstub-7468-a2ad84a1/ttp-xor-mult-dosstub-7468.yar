rule TTP_XOR_MULT_DOSStub_7468 {
  strings:
    $key_7468 = { 20 00 [2] 54 18 [2] 13 1a [2] 54 0b [2] 1a 07 [2] 16 0d [2] 01 06 [2] 1a 48 [2] 27 }

  condition:
    any of them
}