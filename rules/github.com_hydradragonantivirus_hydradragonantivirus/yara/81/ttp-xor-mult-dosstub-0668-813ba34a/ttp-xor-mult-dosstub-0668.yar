rule TTP_XOR_MULT_DOSStub_0668 {
  strings:
    $key_0668 = { 52 00 [2] 26 18 [2] 61 1a [2] 26 0b [2] 68 07 [2] 64 0d [2] 73 06 [2] 68 48 [2] 55 }

  condition:
    any of them
}