rule TTP_XOR_MULT_DOSStub_6068 {
  strings:
    $key_6068 = { 34 00 [2] 40 18 [2] 07 1a [2] 40 0b [2] 0e 07 [2] 02 0d [2] 15 06 [2] 0e 48 [2] 33 }

  condition:
    any of them
}