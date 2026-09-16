rule TTP_XOR_MULT_DOSStub_5a1d {
  strings:
    $key_5a1d = { 0e 75 [2] 7a 6d [2] 3d 6f [2] 7a 7e [2] 34 72 [2] 38 78 [2] 2f 73 [2] 34 3d [2] 09 }

  condition:
    any of them
}