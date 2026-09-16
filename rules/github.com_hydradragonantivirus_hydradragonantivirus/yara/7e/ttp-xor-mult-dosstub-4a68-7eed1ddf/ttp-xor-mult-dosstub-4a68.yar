rule TTP_XOR_MULT_DOSStub_4a68 {
  strings:
    $key_4a68 = { 1e 00 [2] 6a 18 [2] 2d 1a [2] 6a 0b [2] 24 07 [2] 28 0d [2] 3f 06 [2] 24 48 [2] 19 }

  condition:
    any of them
}