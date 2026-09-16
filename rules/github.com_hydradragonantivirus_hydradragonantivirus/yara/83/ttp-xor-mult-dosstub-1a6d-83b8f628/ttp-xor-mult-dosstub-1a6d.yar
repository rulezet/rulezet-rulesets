rule TTP_XOR_MULT_DOSStub_1a6d {
  strings:
    $key_1a6d = { 4e 05 [2] 3a 1d [2] 7d 1f [2] 3a 0e [2] 74 02 [2] 78 08 [2] 6f 03 [2] 74 4d [2] 49 }

  condition:
    any of them
}