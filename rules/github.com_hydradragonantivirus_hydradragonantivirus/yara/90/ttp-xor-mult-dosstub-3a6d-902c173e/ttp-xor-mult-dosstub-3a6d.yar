rule TTP_XOR_MULT_DOSStub_3a6d {
  strings:
    $key_3a6d = { 6e 05 [2] 1a 1d [2] 5d 1f [2] 1a 0e [2] 54 02 [2] 58 08 [2] 4f 03 [2] 54 4d [2] 69 }

  condition:
    any of them
}