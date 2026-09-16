rule TTP_XOR_MULT_DOSStub_5353 {
  strings:
    $key_5353 = { 07 3b [2] 73 23 [2] 34 21 [2] 73 30 [2] 3d 3c [2] 31 36 [2] 26 3d [2] 3d 73 [2] 00 }

  condition:
    any of them
}