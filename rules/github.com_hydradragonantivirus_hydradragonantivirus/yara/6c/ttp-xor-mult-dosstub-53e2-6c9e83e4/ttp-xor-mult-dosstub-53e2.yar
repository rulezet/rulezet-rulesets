rule TTP_XOR_MULT_DOSStub_53e2 {
  strings:
    $key_53e2 = { 07 8a [2] 73 92 [2] 34 90 [2] 73 81 [2] 3d 8d [2] 31 87 [2] 26 8c [2] 3d c2 [2] 00 }

  condition:
    any of them
}