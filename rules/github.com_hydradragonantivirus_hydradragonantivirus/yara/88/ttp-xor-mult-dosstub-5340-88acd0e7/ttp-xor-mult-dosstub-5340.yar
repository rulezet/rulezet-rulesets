rule TTP_XOR_MULT_DOSStub_5340 {
  strings:
    $key_5340 = { 07 28 [2] 73 30 [2] 34 32 [2] 73 23 [2] 3d 2f [2] 31 25 [2] 26 2e [2] 3d 60 [2] 00 }

  condition:
    any of them
}