rule TTP_XOR_MULT_DOSStub_3a53 {
  strings:
    $key_3a53 = { 6e 3b [2] 1a 23 [2] 5d 21 [2] 1a 30 [2] 54 3c [2] 58 36 [2] 4f 3d [2] 54 73 [2] 69 }

  condition:
    any of them
}