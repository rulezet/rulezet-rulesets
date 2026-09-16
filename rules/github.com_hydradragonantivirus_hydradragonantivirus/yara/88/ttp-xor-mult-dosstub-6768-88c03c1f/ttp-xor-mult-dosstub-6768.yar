rule TTP_XOR_MULT_DOSStub_6768 {
  strings:
    $key_6768 = { 33 00 [2] 47 18 [2] 00 1a [2] 47 0b [2] 09 07 [2] 05 0d [2] 12 06 [2] 09 48 [2] 34 }

  condition:
    any of them
}