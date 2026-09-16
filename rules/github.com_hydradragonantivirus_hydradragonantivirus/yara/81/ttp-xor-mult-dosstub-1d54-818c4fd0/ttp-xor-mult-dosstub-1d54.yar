rule TTP_XOR_MULT_DOSStub_1d54 {
  strings:
    $key_1d54 = { 49 3c [2] 3d 24 [2] 7a 26 [2] 3d 37 [2] 73 3b [2] 7f 31 [2] 68 3a [2] 73 74 [2] 4e }

  condition:
    any of them
}