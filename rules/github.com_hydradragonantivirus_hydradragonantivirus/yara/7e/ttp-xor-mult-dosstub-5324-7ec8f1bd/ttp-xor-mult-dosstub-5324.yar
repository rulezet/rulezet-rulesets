rule TTP_XOR_MULT_DOSStub_5324 {
  strings:
    $key_5324 = { 07 4c [2] 73 54 [2] 34 56 [2] 73 47 [2] 3d 4b [2] 31 41 [2] 26 4a [2] 3d 04 [2] 00 }

  condition:
    any of them
}