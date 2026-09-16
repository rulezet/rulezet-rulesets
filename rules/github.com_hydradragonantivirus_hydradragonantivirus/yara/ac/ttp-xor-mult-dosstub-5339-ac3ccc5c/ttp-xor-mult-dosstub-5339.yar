rule TTP_XOR_MULT_DOSStub_5339 {
  strings:
    $key_5339 = { 07 51 [2] 73 49 [2] 34 4b [2] 73 5a [2] 3d 56 [2] 31 5c [2] 26 57 [2] 3d 19 [2] 00 }

  condition:
    any of them
}