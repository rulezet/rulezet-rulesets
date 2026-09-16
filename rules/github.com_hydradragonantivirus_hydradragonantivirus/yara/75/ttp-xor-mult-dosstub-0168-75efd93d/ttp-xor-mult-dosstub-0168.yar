rule TTP_XOR_MULT_DOSStub_0168 {
  strings:
    $key_0168 = { 55 00 [2] 21 18 [2] 66 1a [2] 21 0b [2] 6f 07 [2] 63 0d [2] 74 06 [2] 6f 48 [2] 52 }

  condition:
    any of them
}