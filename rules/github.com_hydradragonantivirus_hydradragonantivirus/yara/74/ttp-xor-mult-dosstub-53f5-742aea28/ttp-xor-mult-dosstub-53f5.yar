rule TTP_XOR_MULT_DOSStub_53f5 {
  strings:
    $key_53f5 = { 07 9d [2] 73 85 [2] 34 87 [2] 73 96 [2] 3d 9a [2] 31 90 [2] 26 9b [2] 3d d5 [2] 00 }

  condition:
    any of them
}