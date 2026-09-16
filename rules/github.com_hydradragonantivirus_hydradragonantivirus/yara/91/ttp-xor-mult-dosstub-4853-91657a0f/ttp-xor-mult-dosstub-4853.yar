rule TTP_XOR_MULT_DOSStub_4853 {
  strings:
    $key_4853 = { 1c 3b [2] 68 23 [2] 2f 21 [2] 68 30 [2] 26 3c [2] 2a 36 [2] 3d 3d [2] 26 73 [2] 1b }

  condition:
    any of them
}