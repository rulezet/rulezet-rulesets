rule TTP_XOR_MULT_DOSStub_5316 {
  strings:
    $key_5316 = { 07 7e [2] 73 66 [2] 34 64 [2] 73 75 [2] 3d 79 [2] 31 73 [2] 26 78 [2] 3d 36 [2] 00 }

  condition:
    any of them
}