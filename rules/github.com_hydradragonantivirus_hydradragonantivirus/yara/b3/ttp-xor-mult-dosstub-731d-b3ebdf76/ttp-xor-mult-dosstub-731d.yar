rule TTP_XOR_MULT_DOSStub_731d {
  strings:
    $key_731d = { 27 75 [2] 53 6d [2] 14 6f [2] 53 7e [2] 1d 72 [2] 11 78 [2] 06 73 [2] 1d 3d [2] 20 }

  condition:
    any of them
}