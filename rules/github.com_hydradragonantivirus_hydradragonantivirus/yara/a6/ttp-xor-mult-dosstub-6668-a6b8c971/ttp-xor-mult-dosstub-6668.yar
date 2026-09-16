rule TTP_XOR_MULT_DOSStub_6668 {
  strings:
    $key_6668 = { 32 00 [2] 46 18 [2] 01 1a [2] 46 0b [2] 08 07 [2] 04 0d [2] 13 06 [2] 08 48 [2] 35 }

  condition:
    any of them
}