rule TTP_XOR_MULT_DOSStub_5346 {
  strings:
    $key_5346 = { 07 2e [2] 73 36 [2] 34 34 [2] 73 25 [2] 3d 29 [2] 31 23 [2] 26 28 [2] 3d 66 [2] 00 }

  condition:
    any of them
}