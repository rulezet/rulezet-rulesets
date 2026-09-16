rule TTP_XOR_MULT_DOSStub_6568 {
  strings:
    $key_6568 = { 31 00 [2] 45 18 [2] 02 1a [2] 45 0b [2] 0b 07 [2] 07 0d [2] 10 06 [2] 0b 48 [2] 36 }

  condition:
    any of them
}