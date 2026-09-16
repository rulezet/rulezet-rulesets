rule TTP_XOR_MULT_DOSStub_547c {
  strings:
    $key_547c = { 00 14 [2] 74 0c [2] 33 0e [2] 74 1f [2] 3a 13 [2] 36 19 [2] 21 12 [2] 3a 5c [2] 07 }

  condition:
    any of them
}