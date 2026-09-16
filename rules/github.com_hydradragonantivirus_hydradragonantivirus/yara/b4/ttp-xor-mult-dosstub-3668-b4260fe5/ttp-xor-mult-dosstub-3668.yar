rule TTP_XOR_MULT_DOSStub_3668 {
  strings:
    $key_3668 = { 62 00 [2] 16 18 [2] 51 1a [2] 16 0b [2] 58 07 [2] 54 0d [2] 43 06 [2] 58 48 [2] 65 }

  condition:
    any of them
}