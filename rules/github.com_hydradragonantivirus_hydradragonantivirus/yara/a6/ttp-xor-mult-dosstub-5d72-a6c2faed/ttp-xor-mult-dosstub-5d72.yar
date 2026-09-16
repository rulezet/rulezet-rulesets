rule TTP_XOR_MULT_DOSStub_5d72 {
  strings:
    $key_5d72 = { 09 1a [2] 7d 02 [2] 3a 00 [2] 7d 11 [2] 33 1d [2] 3f 17 [2] 28 1c [2] 33 52 [2] 0e }

  condition:
    any of them
}