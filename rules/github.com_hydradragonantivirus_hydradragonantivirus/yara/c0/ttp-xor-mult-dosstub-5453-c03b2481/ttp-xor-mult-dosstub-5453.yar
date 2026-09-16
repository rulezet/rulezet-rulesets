rule TTP_XOR_MULT_DOSStub_5453 {
  strings:
    $key_5453 = { 00 3b [2] 74 23 [2] 33 21 [2] 74 30 [2] 3a 3c [2] 36 36 [2] 21 3d [2] 3a 73 [2] 07 }

  condition:
    any of them
}