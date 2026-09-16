rule TTP_XOR_MULT_DOSStub_1f68 {
  strings:
    $key_1f68 = { 4b 00 [2] 3f 18 [2] 78 1a [2] 3f 0b [2] 71 07 [2] 7d 0d [2] 6a 06 [2] 71 48 [2] 4c }

  condition:
    any of them
}