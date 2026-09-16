rule TTP_XOR_MULT_DOSStub_5333 {
  strings:
    $key_5333 = { 07 5b [2] 73 43 [2] 34 41 [2] 73 50 [2] 3d 5c [2] 31 56 [2] 26 5d [2] 3d 13 [2] 00 }

  condition:
    any of them
}