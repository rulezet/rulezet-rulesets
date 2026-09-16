rule TTP_XOR_MULT_DOSStub_4a53 {
  strings:
    $key_4a53 = { 1e 3b [2] 6a 23 [2] 2d 21 [2] 6a 30 [2] 24 3c [2] 28 36 [2] 3f 3d [2] 24 73 [2] 19 }

  condition:
    any of them
}