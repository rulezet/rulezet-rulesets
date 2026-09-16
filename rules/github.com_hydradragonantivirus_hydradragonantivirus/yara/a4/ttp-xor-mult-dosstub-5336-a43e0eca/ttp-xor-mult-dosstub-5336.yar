rule TTP_XOR_MULT_DOSStub_5336 {
  strings:
    $key_5336 = { 07 5e [2] 73 46 [2] 34 44 [2] 73 55 [2] 3d 59 [2] 31 53 [2] 26 58 [2] 3d 16 [2] 00 }

  condition:
    any of them
}