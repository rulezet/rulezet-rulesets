rule TTP_XOR_MULT_DOSStub_546d {
  strings:
    $key_546d = { 00 05 [2] 74 1d [2] 33 1f [2] 74 0e [2] 3a 02 [2] 36 08 [2] 21 03 [2] 3a 4d [2] 07 }

  condition:
    any of them
}