rule TTP_XOR_MULT_DOSStub_5374 {
  strings:
    $key_5374 = { 07 1c [2] 73 04 [2] 34 06 [2] 73 17 [2] 3d 1b [2] 31 11 [2] 26 1a [2] 3d 54 [2] 00 }

  condition:
    any of them
}