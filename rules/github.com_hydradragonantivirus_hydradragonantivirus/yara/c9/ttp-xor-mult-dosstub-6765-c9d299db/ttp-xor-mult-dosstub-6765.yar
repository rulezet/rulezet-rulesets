rule TTP_XOR_MULT_DOSStub_6765 {
  strings:
    $key_6765 = { 33 0d [2] 47 15 [2] 00 17 [2] 47 06 [2] 09 0a [2] 05 00 [2] 12 0b [2] 09 45 [2] 34 }

  condition:
    any of them
}