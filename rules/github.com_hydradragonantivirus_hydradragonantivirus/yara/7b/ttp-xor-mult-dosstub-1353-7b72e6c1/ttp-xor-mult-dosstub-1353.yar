rule TTP_XOR_MULT_DOSStub_1353 {
  strings:
    $key_1353 = { 47 3b [2] 33 23 [2] 74 21 [2] 33 30 [2] 7d 3c [2] 71 36 [2] 66 3d [2] 7d 73 [2] 40 }

  condition:
    any of them
}