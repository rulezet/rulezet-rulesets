rule TTP_XOR_MULT_DOSStub_244d {
  strings:
    $key_244d = { 70 25 [2] 04 3d [2] 43 3f [2] 04 2e [2] 4a 22 [2] 46 28 [2] 51 23 [2] 4a 6d [2] 77 }

  condition:
    any of them
}