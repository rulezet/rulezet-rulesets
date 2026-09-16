rule TTP_XOR_MULT_DOSStub_5a68 {
  strings:
    $key_5a68 = { 0e 00 [2] 7a 18 [2] 3d 1a [2] 7a 0b [2] 34 07 [2] 38 0d [2] 2f 06 [2] 34 48 [2] 09 }

  condition:
    any of them
}