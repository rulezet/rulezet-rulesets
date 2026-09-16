rule TTP_XOR_MULT_DOSStub_5322 {
  strings:
    $key_5322 = { 07 4a [2] 73 52 [2] 34 50 [2] 73 41 [2] 3d 4d [2] 31 47 [2] 26 4c [2] 3d 02 [2] 00 }

  condition:
    any of them
}