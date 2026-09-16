rule TTP_XOR_MULT_DOSStub_4a6d {
  strings:
    $key_4a6d = { 1e 05 [2] 6a 1d [2] 2d 1f [2] 6a 0e [2] 24 02 [2] 28 08 [2] 3f 03 [2] 24 4d [2] 19 }

  condition:
    any of them
}