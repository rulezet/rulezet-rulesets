rule TTP_XOR_MULT_DOSStub_5168 {
  strings:
    $key_5168 = { 05 00 [2] 71 18 [2] 36 1a [2] 71 0b [2] 3f 07 [2] 33 0d [2] 24 06 [2] 3f 48 [2] 02 }

  condition:
    any of them
}