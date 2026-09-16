rule TTP_XOR_MULT_DOSStub_1a53 {
  strings:
    $key_1a53 = { 4e 3b [2] 3a 23 [2] 7d 21 [2] 3a 30 [2] 74 3c [2] 78 36 [2] 6f 3d [2] 74 73 [2] 49 }

  condition:
    any of them
}