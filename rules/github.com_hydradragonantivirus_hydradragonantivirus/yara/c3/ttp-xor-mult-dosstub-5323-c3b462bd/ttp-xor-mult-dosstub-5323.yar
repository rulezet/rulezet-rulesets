rule TTP_XOR_MULT_DOSStub_5323 {
  strings:
    $key_5323 = { 07 4b [2] 73 53 [2] 34 51 [2] 73 40 [2] 3d 4c [2] 31 46 [2] 26 4d [2] 3d 03 [2] 00 }

  condition:
    any of them
}