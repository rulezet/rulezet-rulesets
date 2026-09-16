rule TTP_XOR_MULT_DOSStub_546a {
  strings:
    $key_546a = { 00 02 [2] 74 1a [2] 33 18 [2] 74 09 [2] 3a 05 [2] 36 0f [2] 21 04 [2] 3a 4a [2] 07 }

  condition:
    any of them
}