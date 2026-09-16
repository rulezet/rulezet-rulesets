rule TTP_XOR_MULT_DOSStub_634d {
  strings:
    $key_634d = { 37 25 [2] 43 3d [2] 04 3f [2] 43 2e [2] 0d 22 [2] 01 28 [2] 16 23 [2] 0d 6d [2] 30 }

  condition:
    any of them
}