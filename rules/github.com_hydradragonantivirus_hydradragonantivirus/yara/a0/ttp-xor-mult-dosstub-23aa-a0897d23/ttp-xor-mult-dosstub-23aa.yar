rule TTP_XOR_MULT_DOSStub_23aa {
  strings:
    $key_23aa = { 77 c2 [2] 03 da [2] 44 d8 [2] 03 c9 [2] 4d c5 [2] 41 cf [2] 56 c4 [2] 4d 8a [2] 70 }

  condition:
    any of them
}