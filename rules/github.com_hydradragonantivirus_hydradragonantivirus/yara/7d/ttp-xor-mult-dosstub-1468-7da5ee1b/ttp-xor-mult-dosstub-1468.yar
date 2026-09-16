rule TTP_XOR_MULT_DOSStub_1468 {
  strings:
    $key_1468 = { 40 00 [2] 34 18 [2] 73 1a [2] 34 0b [2] 7a 07 [2] 76 0d [2] 61 06 [2] 7a 48 [2] 47 }

  condition:
    any of them
}