rule TTP_XOR_MULT_DOSStub_451d {
  strings:
    $key_451d = { 11 75 [2] 65 6d [2] 22 6f [2] 65 7e [2] 2b 72 [2] 27 78 [2] 30 73 [2] 2b 3d [2] 16 }

  condition:
    any of them
}