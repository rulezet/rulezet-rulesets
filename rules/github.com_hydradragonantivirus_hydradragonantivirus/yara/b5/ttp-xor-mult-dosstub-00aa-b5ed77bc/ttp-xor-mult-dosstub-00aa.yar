rule TTP_XOR_MULT_DOSStub_00aa {
  strings:
    $key_00aa = { 54 c2 [2] 20 da [2] 67 d8 [2] 20 c9 [2] 6e c5 [2] 62 cf [2] 75 c4 [2] 6e 8a [2] 53 }

  condition:
    any of them
}