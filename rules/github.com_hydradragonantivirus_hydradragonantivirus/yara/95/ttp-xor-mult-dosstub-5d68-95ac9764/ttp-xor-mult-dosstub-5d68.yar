rule TTP_XOR_MULT_DOSStub_5d68 {
  strings:
    $key_5d68 = { 09 00 [2] 7d 18 [2] 3a 1a [2] 7d 0b [2] 33 07 [2] 3f 0d [2] 28 06 [2] 33 48 [2] 0e }

  condition:
    any of them
}