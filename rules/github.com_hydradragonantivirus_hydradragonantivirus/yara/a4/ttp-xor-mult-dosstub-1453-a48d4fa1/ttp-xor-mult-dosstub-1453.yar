rule TTP_XOR_MULT_DOSStub_1453 {
  strings:
    $key_1453 = { 40 3b [2] 34 23 [2] 73 21 [2] 34 30 [2] 7a 3c [2] 76 36 [2] 61 3d [2] 7a 73 [2] 47 }

  condition:
    any of them
}