rule TTP_XOR_MULT_DOSStub_5373 {
  strings:
    $key_5373 = { 07 1b [2] 73 03 [2] 34 01 [2] 73 10 [2] 3d 1c [2] 31 16 [2] 26 1d [2] 3d 53 [2] 00 }

  condition:
    any of them
}