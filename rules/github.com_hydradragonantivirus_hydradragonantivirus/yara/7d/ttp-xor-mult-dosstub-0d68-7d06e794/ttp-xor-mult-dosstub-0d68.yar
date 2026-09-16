rule TTP_XOR_MULT_DOSStub_0d68 {
  strings:
    $key_0d68 = { 59 00 [2] 2d 18 [2] 6a 1a [2] 2d 0b [2] 63 07 [2] 6f 0d [2] 78 06 [2] 63 48 [2] 5e }

  condition:
    any of them
}