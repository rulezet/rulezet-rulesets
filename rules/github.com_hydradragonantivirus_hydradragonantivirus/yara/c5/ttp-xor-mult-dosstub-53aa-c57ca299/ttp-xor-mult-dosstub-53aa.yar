rule TTP_XOR_MULT_DOSStub_53aa {
  strings:
    $key_53aa = { 07 c2 [2] 73 da [2] 34 d8 [2] 73 c9 [2] 3d c5 [2] 31 cf [2] 26 c4 [2] 3d 8a [2] 00 }

  condition:
    any of them
}