rule TTP_XOR_MULT_DOSStub_274d {
  strings:
    $key_274d = { 73 25 [2] 07 3d [2] 40 3f [2] 07 2e [2] 49 22 [2] 45 28 [2] 52 23 [2] 49 6d [2] 74 }

  condition:
    any of them
}