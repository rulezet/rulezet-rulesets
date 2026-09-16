rule TTP_XOR_MULT_DOSStub_5306 {
  strings:
    $key_5306 = { 07 6e [2] 73 76 [2] 34 74 [2] 73 65 [2] 3d 69 [2] 31 63 [2] 26 68 [2] 3d 26 [2] 00 }

  condition:
    any of them
}