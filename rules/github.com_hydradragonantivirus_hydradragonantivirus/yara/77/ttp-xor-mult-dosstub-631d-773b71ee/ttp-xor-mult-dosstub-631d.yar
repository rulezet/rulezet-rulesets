rule TTP_XOR_MULT_DOSStub_631d {
  strings:
    $key_631d = { 37 75 [2] 43 6d [2] 04 6f [2] 43 7e [2] 0d 72 [2] 01 78 [2] 16 73 [2] 0d 3d [2] 30 }

  condition:
    any of them
}